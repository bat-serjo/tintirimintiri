#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>

#include <sys/mman.h>
#include <limits.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "tintiri.h"


void encrypt(){}
void decrypt(){}

const size_t PAGE_SIZE = 4096;
size_t PAGE_MASK = ~(PAGE_SIZE - 1);
#define PAGE_ALIGN(addr) ((size_t)(addr) & PAGE_MASK)

//struct chunk {
//    uint64_t offset;
//    uint64_t size;
//};
//
//
//struct _settings {
//    char name[4096];
//    struct chunk chunks[8];
//};
//
//__attribute__((visibility("default"))) struct _settings setup ;


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
    struct my_ucontext_t* c = (struct my_ucontext_t* )context;
//    for (int  _=0; _<NGREG; _++) {
//        printf("REG%2d: %llx\n", _, c->uc_mcontext.gregs[_]);
//    }
//    printf("REG_RIP: %llx\n", c->uc_mcontext.gregs[REG_RIP]);
    uint8_t *p = (uint8_t*)c->uc_mcontext.gregs[REG_RIP];
    mprotect((void*)PAGE_ALIGN(p), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
    *p = 0x90;
//    printf("\n");
}

void _handle_ILL(int signum, siginfo_t *info ,void *context)
{
    struct my_ucontext_t* c = (struct my_ucontext_t* )context;
//    for (int  _=0; _<NGREG; _++) {
//        printf("REG%2d: %llx\n", _, c->uc_mcontext.gregs[_]);
//    }
//    printf("\n");
}

void _handler(int signum, siginfo_t *info ,void *context)
{
    if (signum == SIGILL) {
        return _handle_ILL(signum, info, context);
    }
    
    if (signum == SIGSEGV) {
        return _handle_SEGV(signum, info, context);
    }
}

struct sigaction old_ill, old_segv;
struct sigaction new_action;

int init_signals (void)
{
    struct sigaction new_action = {
        .sa_sigaction = _handler,
        .sa_flags = SA_RESTART,
    };
    
    sigfillset (&new_action.sa_mask);

    sigaction(SIGILL, &new_action, &old_ill);
    sigaction(SIGSEGV, &new_action, &old_segv);
}

#ifndef ENTRY
#define ENTRY 0
#endif

void _start() {
//int main() {
    pmaps_t pms = read_maps(getpid());
    
//    for (int i=0; i<pms.count; i++) {
//        printf("%p %p %d %s\n", pms.chunks[i].start_va, pms.chunks[i].end_va, pms.chunks[i].mode, pms.chunks[i].file_path);
//    }
    
    init_signals();
    
    void* va = NULL;
    for (uint32_t i=0; i < pms.count; i++) {
        if (pms.chunks[i].mode & PROT_EXEC) {
            va = pms.chunks[i].start_va;
            break;
        }
    }
    
    uint64_t a = (uint64_t)va + ENTRY;
    ((void(*)())a)();
    
    asm(".byte 0xf4");
//    exit(0);
}