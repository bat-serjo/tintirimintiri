#define _GNU_SOURCE
#include <stdio.h>
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

size_t PAGE_SIZE = 0;
size_t PAGE_MASK = 0;
#define PAGE_ALIGN(addr) ((size_t)(addr) & PAGE_MASK)

struct chunk {
    uint64_t offset;
    uint64_t size;
};


struct _settings {
    char name[4096];
    struct chunk chunks[8];
};

__attribute__((visibility("default"))) struct _settings setup ;


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


ssize_t read_fd_line(char** line, size_t* len, int fd) {
    const size_t _chunk=256;
    ssize_t cnt=0;
    ssize_t ret = 0;
    char* cline = *line;
    
    if (cline == NULL) {
        cline = realloc(cline, _chunk);
    }
    
    while(1) {
        ret = read(fd, &cline[cnt], 1);
        if ( ret <= 0 ) {cline[cnt] = '\0'; break;}
        if (cline[cnt] == '\n') {cline[cnt]='\0'; break;}
        cnt++;
        if (cnt % _chunk == _chunk) {
            cline = realloc(cline, cnt+_chunk);
        }
    }
    
    *line = cline;
    if (len != NULL){
        *len = cnt;
    }
    return cnt;
}


pmaps_t read_maps(uint64_t pid) {
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    
    pmaps_t pmaps = {
        .count = 0,
        .chunks = NULL,
    };
    
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path)-1, "/proc/%ld/maps", pid);
    
    int fd = open(maps_path, O_RDONLY);
    if (fd < 0) {
        return pmaps;
    }

    char* cur_pos;
    while ((read = read_fd_line(&line, &len, fd)) != -1) {
        if (line == NULL || read == 0) break;
        if (line[read-1]=='\n') {line[read-1] = '\0';}
        printf("%s\n", line);
        
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
        
        free(line);
        line = NULL;
        len = 0;
    }
    
    return pmaps;
}


void _handle_SEGV(int signum, siginfo_t *info ,void *context)
{
    struct my_ucontext_t* c = (struct my_ucontext_t* )context;
    for (int  _=0; _<NGREG; _++) {
        printf("REG%2d: %llx\n", _, c->uc_mcontext.gregs[_]);
    }
    printf("REG_RIP: %llx\n", c->uc_mcontext.gregs[REG_RIP]);
    uint8_t *p = (uint8_t*)c->uc_mcontext.gregs[REG_RIP];
    mprotect((void*)PAGE_ALIGN(p), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
    *p = 0x90;
    printf("\n");
}

void _handle_ILL(int signum, siginfo_t *info ,void *context)
{
    struct my_ucontext_t* c = (struct my_ucontext_t* )context;
    for (int  _=0; _<NGREG; _++) {
        printf("REG%2d: %llx\n", _, c->uc_mcontext.gregs[_]);
    }
    printf("\n");
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
struct sigaction new_action = {
    .sa_sigaction = _handler,
    .sa_flags = SA_RESTART,
};

int init_signals (void)
{
    PAGE_SIZE = sysconf(_SC_PAGESIZE);
    PAGE_MASK = ~(PAGE_SIZE - 1);
    
    sigfillset (&new_action.sa_mask);

    sigaction(SIGILL, &new_action, &old_ill);
    sigaction(SIGSEGV, &new_action, &old_segv);
}


int main() {
    pmaps_t pms = read_maps(getpid());
    for (int i=0; i<pms.count; i++) {
        printf("%p %p %d %s\n", pms.chunks[i].start_va, pms.chunks[i].end_va, pms.chunks[i].mode, pms.chunks[i].file_path);
    }
    
    init_signals();
    asm(".byte 0xf4");
}