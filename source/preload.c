#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include "dwhooks-clean.h"

static void* (*real_malloc)(size_t)=NULL;
static ssize_t (*real_read)(int, void*, size_t)=NULL;
static ssize_t (*real_write)(int, const void*, size_t)=NULL;
static int MALLOC_FLAG=0;

static void mtrace_init(void)
{
    real_malloc = (void*(*)( size_t )) dlsym(RTLD_NEXT, "malloc");
    if (NULL == real_malloc) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
}

void *malloc(size_t size)
{
    
    //if (MALLOC_FLAG == 1) {
        if(real_malloc==NULL) {
            mtrace_init();
        }
        void *p = NULL;
        fprintf(stderr, "malloc started: %lu\n", size);
        p = real_malloc(size);
        return p;
        /**
    }
    else {
        MALLOC_FLAG = 1;
        fprintf(stderr, "malloc started\n");
        if(real_malloc==NULL) {
            mtrace_init();
        }

        void *p = NULL;
        fprintf(stderr, "size address: %p", &size);
        get_original_address(&size);
        fprintf(stderr, "malloc started: %lu\n", size);
        p = real_malloc(size);
        MALLOC_FLAG = 0;
        return p;
    }
    */
}

static void read_init(void)
{
    real_read = (ssize_t(*)( int, void*, size_t )) dlsym(RTLD_NEXT, "read");
    if (NULL == real_read) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
}
ssize_t read(int fildes, void *buf, size_t nbyte){
    if (real_read == NULL) {
        read_init();
    }
    get_original_address(&fildes);
    get_original_address(&nbyte);
    ssize_t p = 0;
    fprintf(stderr, "read started: %d,%lu", fildes, nbyte);
    p = real_read(fildes,buf,nbyte);
    return p;
}


static void write_init(void)
{
    real_write = (ssize_t(*)( int, const void*, size_t )) dlsym(RTLD_NEXT, "write");
    if (NULL == real_write) {
        fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
    }
}

ssize_t write(int fildes, const void *buf, size_t nbyte){
    if (real_write == NULL) {
        write_init();
    }
    
    ssize_t p = 0;
    fprintf(stderr, "write started: %d,%lu", fildes, nbyte);
    p = real_write(fildes,buf,nbyte);
    return p;
}


