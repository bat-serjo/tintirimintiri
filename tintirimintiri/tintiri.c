#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/mman.h>
#include <limits.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "errno.h"


#include <signal.h>
//#include <linux/signal.h>

//#include "tintiri.h"


void encrypt(){}
void decrypt(){}

size_t PAGE_SIZE = 0;

uint64_t fail_address;
uint64_t fail_size;
uint64_t copy_address;
uint64_t copy_size;



typedef struct vm_chunk {
    void* start_va; 
    void* end_va;
    uint32_t mode;  
    size_t offset;   
    uint64_t major_id;
    uint64_t minor_id;   
    uint64_t inode_id;   
    char file_path[256];
}vm_chunk_t;

typedef struct pmaps {
    uint32_t count;
    vm_chunk_t* chunks;
}pmaps_t; 

const char NIL = '\0';

ssize_t read_fd_line(char* line, size_t len, int fd) {
    ssize_t cnt=0;
    ssize_t ret = 0;
    
    while(1) {
        ret = read(fd, &line[cnt], 1);
        if ( ret <= 0 ) {line[cnt] = NIL; break;}
        if (line[cnt] == '\n') {line[cnt]=NIL; break;}
        cnt++;
        if (cnt == len-1) {
            line[cnt] = NIL;
        }
    }
    
    return cnt;
}


size_t str_append(char* dst, char* src) {
    size_t len = strlen(src);
    memcpy(dst, src, strlen(src));
    return len;
}

size_t itostr(char *dest, int a, int base) {
  char buffer[sizeof a * CHAR_BIT + 1 + 1]; 
  static const char digits[36] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  if (base < 2 || base > 36) {
    return 0;
  }

  // Start filling from the end
  char* p = &buffer[sizeof buffer - 1];
  *p = NIL;

  // Work with negative `int`
  int an = a < 0 ? a : -a;  

  do {
    *(--p) = digits[-(an % base)];
    an /= base;
  } while (an);

  if (a < 0) {
    *(--p) = '-';
  }

  size_t size_used = &buffer[sizeof(buffer)] - p;
  memcpy(dest, p, size_used);
  return size_used;
}

void* page_align(void* addr) {
    size_t PAGE_MASK = ~(PAGE_SIZE - 1);
    return (void*)((size_t)(addr) & PAGE_MASK);
}

pmaps_t read_maps(uint64_t pid) {
    char line[1024];
    size_t len = 0;
    ssize_t read;
    
    pmaps_t pmaps = {
        .count = 0,
        .chunks = NULL,
    };
    
    char maps_path[256];
    size_t i=0;
    i += str_append(&maps_path[i], "/proc/");
    i += itostr(&maps_path[i], pid, 10);
    i += str_append(&maps_path[i-1], "/maps");
    maps_path[i-1] = NIL;
    
    int fd = open(maps_path, O_RDONLY);
    if (fd < 0) {
        return pmaps;
    }

    char* cur_pos;
    while ((read = read_fd_line(&line[0], len, fd)) != -1) {
        if (line == NULL || read == 0) break;
        if (line[read-1]=='\n') {line[read-1] = NIL;}
        
        pmaps.count++;
        pmaps.chunks = realloc(pmaps.chunks, pmaps.count * sizeof(vm_chunk_t));
        vm_chunk_t* cur_map = &pmaps.chunks[pmaps.count-1]; 
        
        char* tok = strtok_r(line, "-", &cur_pos);
        cur_map->start_va = (void*)strtoull(tok, NULL, 16);
        tok = strtok_r(NULL, " ", &cur_pos);
        cur_map->end_va = (void*)strtoull(tok, NULL, 16);

        tok = strtok_r(NULL, " ", &cur_pos);
        if (tok[0] == 'r'){ cur_map->mode |= PROT_READ; }
        if (tok[1] == 'w'){ cur_map->mode |= PROT_WRITE; }
        if (tok[2] == 'x'){ cur_map->mode |= PROT_EXEC; }
        if (tok[3] == 'p'){ cur_map->mode |= MAP_PRIVATE; }
        if (tok[3] == 's'){ cur_map->mode |= MAP_SHARED; }

        tok = strtok_r(NULL, " ", &cur_pos);
        cur_map->offset = strtoll(tok, NULL, 16);

        tok = strtok_r(NULL, ":", &cur_pos);
        cur_map->major_id = strtoll(tok, NULL, 16);
        tok = strtok_r(NULL, " ", &cur_pos);
        cur_map->minor_id = strtoll(tok, NULL, 16);

        tok = strtok_r(NULL, " ", &cur_pos);
        cur_map->inode_id = strtoll(tok, NULL, 10);
        
        tok = strtok_r(NULL, " ", &cur_pos);
        if (tok != NULL && *tok!='\0') {
            strncpy(&cur_map->file_path[0], tok, sizeof(cur_map->file_path));
        }        
    }
    
    return pmaps;
}


void _handle_SEGV(int signum, siginfo_t *info ,void *context)
{
    void *p = info->si_addr;
    void* pp = page_align(p);

    uint64_t off = (uint64_t)p - fail_address;    
    void* cp = page_align((void*)((uint64_t)copy_address+off));
    
    mprotect((void*)pp, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
    memcpy((void*)pp, (void*)cp, PAGE_SIZE);
    return;
}

struct sigaction new_action;

int init_signals (void)
{
    memset(&new_action, 0, sizeof(new_action));
    new_action.sa_sigaction = _handle_SEGV;
    new_action.sa_flags = SA_SIGINFO | SA_RESTART;
//    sigfillset (&new_action.sa_mask);

    sigaction(SIGSEGV, &new_action, NULL);
}

uint32_t get_page_size() {
    void* new_addr = mmap(NULL, 1, PROT_READ, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    
    pmaps_t after_pms = read_maps(getpid());
    for (uint32_t i=0; i < after_pms.count; i++) {
        if (new_addr == after_pms.chunks[i].start_va) {
            return after_pms.chunks[i].end_va - after_pms.chunks[i].start_va;
        }
    }
    return 0;
}

#ifndef ENTRY
#define ENTRY 0
#endif

#ifndef ENTRY_ID
#define ENTRY_ID 0
#endif

#ifndef COPY_ID
#define COPY_ID 0
#endif



uint64_t logic()  {
    pmaps_t pms = read_maps(getpid());

    uint64_t jmp_addr = 0;

    PAGE_SIZE = get_page_size();
    
    fail_address = 0;
    copy_address = 0;
    
    for (uint32_t i=0; i < pms.count; i++) {
        if (pms.chunks[i].offset == ENTRY_ID) {
            fail_address = (uint64_t)pms.chunks[i].start_va;
            fail_size = pms.chunks[i].end_va-pms.chunks[i].start_va;
            jmp_addr = (uint64_t)pms.chunks[i].start_va + ENTRY;
            mprotect(pms.chunks[i].start_va, fail_size, PROT_NONE);
        }
        if (pms.chunks[i].offset == COPY_ID) {
            copy_address = (uint64_t)pms.chunks[i].start_va;
            copy_size = (uint64_t)pms.chunks[i].end_va - (uint64_t)pms.chunks[i].start_va;
        }
        
        if (fail_address != 0 && copy_address != 0) {
            break;
        }
    }

    
    init_signals();
    
    return jmp_addr;
}

//int main() {
//    logic();
//    asm("movq %rax, 42");
//}

__attribute__ ( ( naked ) ) void _start()  {
    asm("pushq %rax "); 
    asm("pushq %rbx "); 
    asm("pushq %rcx "); 
    asm("pushq %rdx "); 
    asm("pushq %rsp "); 
    asm("pushq %rbp "); 
    asm("pushq %rsi "); 
    asm("pushq %rdi "); 
    asm("pushq %r8  "); 
    asm("pushq %r9  "); 
    asm("pushq %r10 "); 
    asm("pushq %r11 "); 
    asm("pushq %r12 "); 
    asm("pushq %r13 "); 
    asm("pushq %r14 "); 
    asm("pushq %r15 ");  

    logic();
    
    asm("popq %r15 "); 
    asm("popq %r14 "); 
    asm("popq %r13 "); 
    asm("popq %r12 "); 
    asm("popq %r11 "); 
    asm("popq %r10 "); 
    asm("popq %r9  "); 
    asm("popq %r8  "); 
    asm("popq %rdi "); 
    asm("popq %rsi "); 
    asm("popq %rbp "); 
    asm("popq %rsp "); 
    asm("popq %rdx "); 
    asm("popq %rcx "); 
    asm("popq %rbx "); 
    
    asm("movq %rax, %r15");
    asm("popq %rax "); 
    
    asm volatile ("jmp *%r15"); 
    asm("hlt");
}
