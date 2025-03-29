/* Demand loader*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <elf.h>
#include <signal.h>

#define PAGE_SIZE 4096
#define STACK_SIZE 0x20000 

#define AT_NULL         0               /* End of vector */
#define AT_IGNORE       1               /* Entry should be ignored */
#define AT_EXECFD       2               /* File descriptor of program */
#define AT_PHDR         3               /* Program headers for program */
#define AT_PHENT        4               /* Size of program header entry */
#define AT_PHNUM        5               /* Number of program headers */
#define AT_PAGESZ       6               /* System page size */
#define AT_BASE         7               /* Base address of interpreter */
#define AT_FLAGS        8               /* Flags */
#define AT_ENTRY        9               /* Entry point of program */
#define AT_NOTELF       10              /* Program is not ELF */
#define AT_UID          11              /* Real uid */
#define AT_EUID         12              /* Effective uid */
#define AT_GID          13              /* Real gid */
#define AT_EGID         14              /* Effective gid */
#define AT_CLKTCK       17              /* Frequency of times() */
#define AT_SYSINFO      32
#define AT_SYSINFO_EHDR 33

void error_exit(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

int fd;
struct stat st;
Elf64_Ehdr *elf_base;
size_t segment_offset;
size_t segment_vaddr;

void segfault_handler(int signum, siginfo_t *info, void *context) {

    void *fault_addr = info->si_addr; 
    printf("Page fault at address: %p\n", fault_addr);

    if (fault_addr == NULL) {
        fprintf(stderr, "Error: Segmentation fault caused by NULL address (0x0)\n");
        exit(EXIT_FAILURE);
    }

    size_t page_start = (size_t)fault_addr & ~(PAGE_SIZE - 1);

    void *mapped_page = mmap((void *)page_start, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_FIXED, fd, page_start - segment_vaddr + segment_offset);

    if (mapped_page == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    printf("Mapped page at address: %p\n", mapped_page);

}

void setup_signal_handlers() {

    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;  
    sa.sa_sigaction = segfault_handler;  
    sigaction(SIGSEGV, &sa, NULL); 

}

char* setup_stack(char *stack_top, int argc, char *argv[], char *envp[], uint64_t aux_phent, uint64_t aux_phnum) {
    
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)stack_top;
    auxv -= 18;
    
    uintptr_t aux_ignore = (uintptr_t)getauxval(AT_IGNORE);
    uintptr_t aux_execfd = (uintptr_t)getauxval(AT_EXECFD);
    uintptr_t aux_phdr = (uintptr_t)getauxval(AT_PHDR);
    uintptr_t aux_pagesz = (uintptr_t)getauxval(AT_PAGESZ);
    uintptr_t aux_base = (uintptr_t)getauxval(AT_BASE);
    uintptr_t aux_flags = (uintptr_t)getauxval(AT_FLAGS);
    uintptr_t aux_entry = (uintptr_t)getauxval(AT_ENTRY);
    uintptr_t aux_notelf = (uintptr_t)getauxval(AT_NOTELF);
    uintptr_t aux_uid = (uintptr_t)getauxval(AT_UID);
    uintptr_t aux_euid = (uintptr_t)getauxval(AT_EUID);
    uintptr_t aux_gid = (uintptr_t)getauxval(AT_GID);
    uintptr_t aux_egid = (uintptr_t)getauxval(AT_EGID);
    uintptr_t aux_clktck = (uintptr_t)getauxval(AT_CLKTCK);
    uintptr_t aux_sysinfo = (uintptr_t)getauxval(AT_SYSINFO);
    uintptr_t aux_sysinfo_ehdr = (uintptr_t)getauxval(AT_SYSINFO_EHDR);

    auxv[0].a_type = AT_IGNORE;
    auxv[0].a_un.a_val = aux_ignore;
    
    auxv[1].a_type = AT_EXECFD;
    auxv[1].a_un.a_val = aux_execfd;
    
    auxv[2].a_type = AT_PHDR;
    auxv[2].a_un.a_val = aux_phdr;

    auxv[3].a_type = AT_PHENT;
    auxv[3].a_un.a_val = aux_phent;

    auxv[4].a_type = AT_PHNUM;
    auxv[4].a_un.a_val = aux_phnum;
    
    auxv[5].a_type = AT_PAGESZ;
    auxv[5].a_un.a_val = aux_pagesz;
    
    auxv[6].a_type = AT_BASE;
    auxv[6].a_un.a_val = aux_base;
    
    auxv[7].a_type = AT_FLAGS;
    auxv[7].a_un.a_val = aux_flags;

    auxv[8].a_type = AT_ENTRY;
    auxv[8].a_un.a_val = aux_entry;

    auxv[9].a_type = AT_NOTELF;
    auxv[9].a_un.a_val = aux_notelf;
    
    auxv[10].a_type = AT_UID;
    auxv[10].a_un.a_val = aux_uid;
    
    auxv[11].a_type = AT_EUID;
    auxv[11].a_un.a_val = aux_euid;
    
    auxv[12].a_type = AT_GID;
    auxv[12].a_un.a_val = aux_gid;

    auxv[13].a_type = AT_EGID;
    auxv[13].a_un.a_val = aux_egid;

    auxv[14].a_type = AT_CLKTCK;
    auxv[14].a_un.a_val = aux_clktck;
    
    auxv[15].a_type = AT_SYSINFO;
    auxv[15].a_un.a_val = aux_sysinfo;
    
    auxv[16].a_type = AT_SYSINFO_EHDR;
    auxv[16].a_un.a_val = aux_sysinfo_ehdr;
    
    auxv[17].a_type = AT_NULL; 
    auxv[17].a_un.a_val = 0;

    char **sp = (char **)auxv;

    sp--;
    *sp = NULL;

    int last_index;

    for (int i = 0; envp[i] != NULL; i++)  
        last_index = i;               
    
    for (int i = last_index; i >= 0; i--) {
        sp--;
        *sp = envp[i];  
    }

    sp--;  
    *sp = NULL;

    for (int i = argc - 1; i >= 0; i--) {
        sp--;
        *sp = argv[i];
    }
    
    sp--;
    *((int *)sp) = argc;

    return (char *)sp;

}

void stack_check(void* top_of_stack, uint64_t argc, char** argv) {
	
    printf("----- stack check -----\n");

	assert(((uint64_t)top_of_stack) % 8 == 0);
	printf("top of stack is 8-byte aligned\n");

	uint64_t* stack = top_of_stack;
	uint64_t actual_argc = *(stack++);
	printf("argc: %lu\n", actual_argc);
	assert(actual_argc == argc);

	for (int i = 0; i < argc; i++) {
		char* argp = (char*)*(stack++);
		assert(strcmp(argp, argv[i]) == 0);
		printf("arg %d: %s\n", i, argp);
	}
	
    assert(*(stack++) == 0);

	int envp_count = 0;
	while (*(stack++) != 0)
		envp_count++;

	printf("env count: %d\n", envp_count);

	Elf64_auxv_t* auxv_start = (Elf64_auxv_t*)stack;
	Elf64_auxv_t* auxv_null = auxv_start;
	
    while (auxv_null->a_type != AT_NULL) {
		auxv_null++;
	}
	
    printf("aux count: %lu\n", auxv_null - auxv_start);
	printf("----- end stack check -----\n");

}

int load_elf(const char *filename, int argc, char *argv[], char *envp[]) {

    setup_signal_handlers();

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        error_exit("Failed to open ELF file");
    }

    if (fstat(fd, &st) < 0) {
        error_exit("Failed to stat ELF file");
    }

    elf_base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if(elf_base == MAP_FAILED) {
        error_exit("Failed to mmap ELF file");
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_base;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        exit(EXIT_FAILURE);
    }

    uint64_t aux_phdr, aux_phent, aux_phnum;
    aux_phent = ehdr->e_phentsize; 
    aux_phnum = ehdr->e_phnum;    
    printf("PHENT (Size of Program Header Entry): %lu\n", aux_phent);
    printf("PHNUM (Number of Program Headers): %lu\n", aux_phnum);

    Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf_base + ehdr->e_phoff);
   
    for (int i = 0; i < ehdr->e_phnum; i++) {
        printf("Program Header %d: Type = 0x%x\n", i, phdr[i].p_type);
    }

    void *entry_addr = (void *)0x60006e5;
    size_t page_start = (size_t)entry_addr & ~(PAGE_SIZE - 1);

    for (int i = 0; i < ehdr->e_phnum; i++) {
         
        if (phdr[i].p_type == PT_LOAD || phdr[i].p_type == PT_TLS || phdr[i].p_type == PT_PHDR) {
     
            if (entry_addr >= phdr[i].p_vaddr && (void *)entry_addr < (phdr[i].p_vaddr + phdr[i].p_filesz)) {
                segment_offset = phdr[i].p_offset;
                segment_vaddr = phdr[i].p_vaddr;
            }

        }

    }

    printf("Copying to 0x%lx - 0x%lx\n", page_start, page_start + PAGE_SIZE);
    void *segment = mmap((void *)page_start, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, page_start - segment_vaddr + segment_offset);
    if (segment == MAP_FAILED) {
        error_exit("Failed to mmap segment");
    }

    char *stack_top;
    char *stack = mmap((void *)0x7ffffff00000, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    stack_top = stack + STACK_SIZE;

    if (munmap(elf_base, st.st_size) < 0) {
        error_exit("Failed to unmap ELF file");
    }

    
    unsigned long stack_pointer; 
    stack_top = setup_stack(stack_top, argc, argv, envp, aux_phdr, aux_phnum);
    stack_check((void *)stack_top, argc, argv);
    
    asm volatile("mov %0, %%rbx\n" :: "r"((long)0x0) : "rbx");
    asm volatile("mov %0, %%rcx\n" :: "r"((long)0x0) : "rcx");
    asm volatile("mov %0, %%rdx\n" :: "r"((long)0x0) : "rdx");
    asm volatile("mov %0, %%rsi\n" :: "r"((long)0x0) : "rsi");
    asm volatile("mov %0, %%rdi\n" :: "r"((long)0x0) : "rdi");
    asm volatile("mov %0, %%r8\n" :: "r"((long)0x0) : "r8");
    asm volatile("mov %0, %%r9\n" :: "r"((long)0x0) : "r9");
    asm volatile("mov %0, %%r10\n" :: "r"((long)0x0) : "r10");
    asm volatile("mov %0, %%r11\n" :: "r"((long)0x0) : "r11");
    asm volatile("mov %0, %%r12\n" :: "r"((long)0x0) : "r12");
    asm volatile("mov %0, %%r13\n" :: "r"((long)0x0) : "r13");
    asm volatile("mov %0, %%r14\n" :: "r"((long)0x0) : "r14");
    asm volatile("mov %0, %%r15\n" :: "r"((long)0x0) : "r15");
    asm volatile("mov %%rsp, %0" : "=r"(stack_pointer) :: "memory");
    asm volatile("mov %0, %%rsp\n" :: "r"(stack_top) :);
    asm volatile("mov %0, %%rax\n" :: "r"((long)0x0) : "rax");
    asm volatile("movabs $0x60006e5, %%rax\n" "call *%%rax\n" ::: "rax", "memory");
    asm volatile("mov %0, %%rsp\n" :: "r"(stack_pointer) :);
    
    printf("Executed Successfully");
    return 0;

}

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf-file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *new_argv[] = {"./loop", NULL};
    char *new_envp[] = {"PATH=/home/harshit/AOS/Labs/Lab3_1", NULL};
    int new_argc = 1;

    load_elf(argv[1], new_argc, new_argv, new_envp);

    return EXIT_SUCCESS;

}


