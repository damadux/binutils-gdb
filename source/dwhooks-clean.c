#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

typedef __uint64_t uint64_t;
#define MAX_MALLOCS 0xFF0
#define START_MALLOC 0x0000
#define OFFSET 0x10000000000000 /* 1E14 */
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
/* Prototypes for our hooks.  */
static void *dw_realloc_hook (void *, size_t, const void *);
static void *dw_malloc_hook (size_t, const void *);
static void dw_free_hook (void*, const void *);
static void *dw_memalign_hook(size_t, size_t, const void*);

static void *(*old_malloc_hook) (size_t, const void *);
static void *(*old_realloc_hook) (void *, size_t, const void *);
static void (*old_free_hook) (void*, const void *);
static void* (* old_memalign_hook)(size_t, size_t, const void*);

// where we store the allocated size
static size_t *sizes;
static void* *original_address;
static void* *return_address;
FILE *logFile;

// keeps track of where we are in the array
static volatile int count = 0, all_count, free_count;
// pthread_mutex_t lock;

const int debug = 1;

void* get_original_address(void* tainted_address){
    if (count == 0){
        return tainted_address;
    }
    printf("in\n");
    for (int i=1;i<count;i++) {
        if (return_address[i] == tainted_address){
        printf("Original address found: %p\n", original_address);
            return original_address[count];
        }
    
    }
    printf("Address not found: %p\n", tainted_address);
    return tainted_address;
}



uint64_t memory_access(uint64_t base_address, uint64_t mem_address){
    if((base_address>>48) == 0xffff)
    {
      return base_address;
    }
    int save_restore = (__malloc_hook == old_malloc_hook);
    if(!save_restore)
    {
      /* Lock the mutex */
      // pthread_mutex_lock(&lock);
      __malloc_hook = old_malloc_hook;
      __free_hook = old_free_hook;
      __realloc_hook = old_realloc_hook;
      __memalign_hook = old_memalign_hook;

    }
    
    int index = mem_address / OFFSET;
    int base_index = base_address / OFFSET;
    if(base_index != index)
    {
      printf("ERROR : Different indexes for base address and mem address\n");
      printf("Indexes %d vs %d mem_address 0x%lx base_address 0x%lx \n", index, base_index, mem_address, base_address);
      exit(-1);
    }
    if(index == 0 || index >= count-START_MALLOC)
    {
        // this was not allocated by the malloc wrapper or it is on the stack
        if(!save_restore)
        {
            /* Restore our own hooks */
          __malloc_hook = dw_malloc_hook;
          __free_hook = dw_free_hook;
          __realloc_hook = dw_realloc_hook;
          __memalign_hook = dw_memalign_hook;
          /* Unlock the mutex */
          // pthread_mutex_unlock(&lock);
        }
        return base_address;
    }
    
    void *address = (void *)( mem_address % OFFSET);
    void *original = original_address[index];
    int size = sizes[index];
    /* Check that the address is within the bounds of the original malloc */
    if (address>=original && address<(original+size)){
        if(!save_restore)
        {
            /* Restore our own hooks */
          __malloc_hook = dw_malloc_hook;
          __free_hook = dw_free_hook;
          __realloc_hook = dw_realloc_hook;     
          __memalign_hook = dw_memalign_hook;
          /* Unlock the mutex */
          // pthread_mutex_unlock(&lock);
        }
        return (base_address % OFFSET);
    }
    else{
      if(address>=original - 0x10 && address<(original+size))
      {
        // printf("WARNING : Accessing the header of a malloced block \n");
          /* Restore our own hooks */
        if(!save_restore)
        {
            /* Restore our own hooks */
          __malloc_hook = dw_malloc_hook;
          __free_hook = dw_free_hook;
          __realloc_hook = dw_realloc_hook;     
          __memalign_hook = dw_memalign_hook;
          /* Unlock the mutex */
          // pthread_mutex_unlock(&lock);
        }
        return (base_address % OFFSET);
      }
      fprintf(logFile,"ERROR : Out of bound dereferencing of address %p \n\
      occured at address %p \n\
      allocated at address %p\n", 
      (void *) mem_address, __builtin_return_address(0), return_address[index]);
      fprintf(logFile,"address %p vs base address %p + size %d\n", address, original, size);
      /* FIXME (for debug purpose) */
      if(!save_restore)
      {
          /* Restore our own hooks */
        __malloc_hook = dw_malloc_hook;
        __free_hook = dw_free_hook;
        __realloc_hook = dw_realloc_hook;     
        __memalign_hook = dw_memalign_hook;
        /* Unlock the mutex */
        // pthread_mutex_unlock(&lock);
      }
      return (base_address % OFFSET);

      exit(-1);
    }
}

uint64_t memory_access_dbg(uint64_t base_address, uint64_t mem_address){
    int save_restore = (__malloc_hook == old_malloc_hook);
    if(!save_restore)
    {
      /* Lock the mutex */
      // pthread_mutex_lock(&lock);
      __malloc_hook = old_malloc_hook;
      __free_hook = old_free_hook;
      __realloc_hook = old_realloc_hook;
      __memalign_hook = old_memalign_hook;

    }
    
    int index = mem_address / OFFSET;
    int base_index = base_address / OFFSET;
    if(base_index != index)
    {
      printf("ERROR : Different indexes for base address and mem address\n");
      printf("Indexes %d vs %d mem_address 0x%lx base_address 0x%lx \n", index, base_index, mem_address, base_address);
      exit(-1);
    }
    if(index == 0 || index >= count-START_MALLOC)
    {
        // this was not allocated by the malloc wrapper or it is on the stack
        if(!save_restore)
        {
            /* Restore our own hooks */
          __malloc_hook = dw_malloc_hook;
          __free_hook = dw_free_hook;
          __realloc_hook = dw_realloc_hook;
          __memalign_hook = dw_memalign_hook;
          /* Unlock the mutex */
          // pthread_mutex_unlock(&lock);
        }
        return base_address;
    }
    
    void *address = (void *)( mem_address % OFFSET);
    void *original = original_address[index];
    int size = sizes[index];
    /* Check that the address is within the bounds of the original malloc */
    if (address>=original && address<(original+size)){
        if(!save_restore)
        {
            /* Restore our own hooks */
          __malloc_hook = dw_malloc_hook;
          __free_hook = dw_free_hook;
          __realloc_hook = dw_realloc_hook;     
          __memalign_hook = dw_memalign_hook;
          /* Unlock the mutex */
          // pthread_mutex_unlock(&lock);
        }
        return (base_address % OFFSET);
    }
    else{
      if(address>=original - 0x10 && address<(original+size))
      {
        // printf("WARNING : Accessing the header of a malloced block \n");
          /* Restore our own hooks */
        if(!save_restore)
        {
            /* Restore our own hooks */
          __malloc_hook = dw_malloc_hook;
          __free_hook = dw_free_hook;
          __realloc_hook = dw_realloc_hook;     
          __memalign_hook = dw_memalign_hook;
          /* Unlock the mutex */
          // pthread_mutex_unlock(&lock);
        }
        return (base_address % OFFSET);
      }
      fprintf(logFile,"ERROR : Out of bound dereferencing of address %p \n\
      occured at address %p \n\
      allocated at address %p\n", 
      (void *) mem_address, __builtin_return_address(0), return_address[index]);
      fprintf(logFile,"address %p vs base address %p + size %d\n", address, original, size);
      /* FIXME (for debug purpose) */
      if(!save_restore)
      {
          /* Restore our own hooks */
        __malloc_hook = dw_malloc_hook;
        __free_hook = dw_free_hook;
        __realloc_hook = dw_realloc_hook;     
        __memalign_hook = dw_memalign_hook;
        /* Unlock the mutex */
        // pthread_mutex_unlock(&lock);
      }
      return (base_address % OFFSET);

      exit(-1);
    }
}

/* Initialize the malloc hooks and allocate the buffers */
static void
dw_init (void)
{
  if (count==1)
  {
    return;
  }
  // pthread_mutex_init(&lock,NULL);
  sizes = (size_t*) malloc(sizeof(size_t) * MAX_MALLOCS);
  original_address = (void**) malloc(sizeof(void *) * MAX_MALLOCS);
  return_address = (void**) malloc(sizeof(void *) * MAX_MALLOCS);
  logFile = stdout; //fopen("log.txt","a+");
  old_malloc_hook = __malloc_hook;
  old_free_hook = __free_hook;
  old_realloc_hook = __realloc_hook;
  __malloc_hook = dw_malloc_hook;
  __free_hook = dw_free_hook;
  __realloc_hook = dw_realloc_hook;     
  __memalign_hook = dw_memalign_hook;
  count = 1;
  all_count = 0;
  free_count = 0;
}

static void *
dw_malloc_hook (size_t size, const void *caller)
{
  all_count++;
  void *result;
  /* Lock the mutex */
  // pthread_mutex_lock(&lock);
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  __realloc_hook = old_realloc_hook;
  __memalign_hook = old_memalign_hook;

  /* Call recursively */
  result = malloc (size);
  fprintf(logFile,"%p",result);
  result = (void *)((uint64_t)result % OFFSET);
  fprintf(logFile,"0x%x Malloc of size %ld returned %p \n", count-START_MALLOC, size, result);
  if(result == NULL)
  {
    /* Restore our hooks and return */
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;     
    __memalign_hook = dw_memalign_hook;
    /* Unlock the mutex */
    // pthread_mutex_unlock(&lock);
    return result;
  }

  /* printf might call malloc, so protect it too if called. */

  unsigned long return_addr = (unsigned long)__builtin_return_address(0);
  /* We check the return address in order not to mess up library calls. */
  if(count>START_MALLOC && count<MAX_MALLOCS+START_MALLOC) //return_addr<0x700000000000 && 
    {
      // printf("count \n%d\n\n", count);
      printf("hit\n");
      original_address[count-START_MALLOC] = result;
      return_address[count-START_MALLOC] = (void *) return_addr;
      result+= OFFSET*(count-START_MALLOC);
      sizes[count-START_MALLOC] = max(size,24);
      
    }
  count++;
  if(debug) {
    printf ("malloc (%u) returns %p\n", (unsigned int) size, result);
    printf ("original: %p\n", original_address[count-1-START_MALLOC]);
    printf ("return: %p\n", return_address[count-1-START_MALLOC]);
  }
  /* Restore our own hooks */
  __malloc_hook = dw_malloc_hook;
  __free_hook = dw_free_hook;
  __realloc_hook = dw_realloc_hook;     
  __memalign_hook = dw_memalign_hook;
  /* Unlock the mutex */
  // pthread_mutex_unlock(&lock);
  return result;
}

static void *
dw_realloc_hook (void *ptr, size_t size, const void *caller)
{
  all_count++;
  void *result;
  /* Lock the mutex */
  // pthread_mutex_lock(&lock);
  /* Restore old hook */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  __realloc_hook = old_realloc_hook;
  __memalign_hook = old_memalign_hook;
  /* Call recursively */
  void *ptr_corrected = (void*) memory_access((uint64_t)ptr,(uint64_t)ptr);
  /* Free ptr_corrected */
  int index = (uint64_t) ptr / OFFSET;
  if(index!=0)
  {
    if(sizes[index]==-100){
        fprintf(logFile,"ERROR : realloc area already freed %p\n", ptr_corrected);
    }
    /*This will generate a failure of memory address if pointer is dereferenced afterwards */
    if(index!=0) sizes[index] = -100;
  }
  result = realloc (ptr_corrected, size);
  // fprintf(logFile,"0x%x Realloc of size %ld returned %p on initial address %p \n", count-START_MALLOC, size, result, ptr_corrected);
  result = (void *)((uint64_t)result % OFFSET);

  if(result == NULL)
  {
    /* Restore our hooks and return */
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;     
    __memalign_hook = dw_memalign_hook;
  
    /* Unlock the mutex */
    // pthread_mutex_unlock(&lock);
    return result;
  }


  /* printf might call malloc, so protect it too. */
  if(debug)
    printf ("realloc (%u) returns %p\n", (unsigned int) size, result);
  unsigned long return_addr = (unsigned long)__builtin_return_address(0);
  if(count>START_MALLOC && (count-START_MALLOC)<MAX_MALLOCS ) //return_addr<0x700000000000 && && count!=43
    {
      original_address[count-START_MALLOC] = result;
      return_address[count-START_MALLOC] = (void *) return_addr;
      result+= OFFSET*(count-START_MALLOC);
      sizes[count-START_MALLOC] = max(size,24);
      // printf("wrapper count %d\n",count);
      
    }
  count++;
  /* Restore our own hook */
  __malloc_hook = dw_malloc_hook;
  __free_hook = dw_free_hook;
  __realloc_hook = dw_realloc_hook;     
  __memalign_hook = dw_memalign_hook;
  /* Unlock the mutex */
  // pthread_mutex_unlock(&lock);
  return result;
}


static void *dw_memalign_hook(size_t alignment, size_t size, const void *caller)
{
  all_count++;
  void *result;
  /* Lock the mutex */
  // pthread_mutex_lock(&lock);
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  __realloc_hook = old_realloc_hook;
  __memalign_hook = old_memalign_hook;
  /* Call recursively */
  posix_memalign(&result, alignment, size);
  result = (void *)((uint64_t)result % OFFSET);
  // fprintf(logFile,"0x%x Memalign of size %ld returned %p \n", count-START_MALLOC, size, result);
  
  if(result == NULL)
  {
    /* Restore our hooks and return */
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;
    __memalign_hook = dw_memalign_hook;
    /* Unlock the mutex */
    // pthread_mutex_unlock(&lock);
    return result;
  }

  /* printf might call malloc, so protect it too if called. */

  unsigned long return_addr = (unsigned long)__builtin_return_address(0);
  /* We check the return address in order not to mess up library calls. */
  if(count>START_MALLOC && count<MAX_MALLOCS+START_MALLOC) //return_addr<0x700000000000 && 
    {
      // printf("count \n%d\n\n", count);
      original_address[count-START_MALLOC] = result;
      return_address[count-START_MALLOC] = (void *) return_addr;
      result+= OFFSET*(count-START_MALLOC);
      sizes[count-START_MALLOC] = max(size,24);
      
    }
  count++;
  if(debug)
    printf ("malloc (%u) returns %p\n", (unsigned int) size, result);
  /* Restore our own hooks */
  __malloc_hook = dw_malloc_hook;
  __free_hook = dw_free_hook;
  __realloc_hook = dw_realloc_hook;     
  __memalign_hook = dw_memalign_hook;
  /* Unlock the mutex */
  // pthread_mutex_unlock(&lock);
  return result;
}

static void
dw_free_hook (void *ptr, const void *caller)
{
  free_count++;
  /* Lock the mutex */
  // pthread_mutex_lock(&lock);
  int index = (uint64_t) ptr / OFFSET;
  void *real_address = (void *)((uint64_t) ptr % OFFSET);
  
  /* Restore all old hooks */
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  __realloc_hook = old_realloc_hook;
  __memalign_hook = old_memalign_hook;

  if(sizes[index]==-100){
      fprintf(logFile,"ERROR : area already freed %p\n", real_address);
  }

  /*This will generate a failure of memory address if pointer is dereferenced afterwards */
  if(index!=0) sizes[index] = -100;  
  if(debug)
    printf("Freeing address %p with index %d original address %p\n", real_address, index, original_address[index]);
  // if((uint64_t)real_address==0x5555555b33b0)
  //   fprintf(logFile,"0x%x Freed area at address %p \n",index, real_address);

  /* Call recursively */
  free (real_address);
  // if(index == 13 || (uint64_t)real_address == 0x555558edfc80 ||(uint64_t)real_address == 0x555558de45c0)
    /* Save underlying hooks */

  /* Restore our own hooks */
  __malloc_hook = dw_malloc_hook;
  __free_hook = dw_free_hook;
  __realloc_hook = dw_realloc_hook;     
  __memalign_hook = dw_memalign_hook;
  /* Unlock the mutex */
  // pthread_mutex_unlock(&lock);
  return;
}

void final_check(){
  __malloc_hook = old_malloc_hook;
  __free_hook = old_free_hook;
  __realloc_hook = old_realloc_hook;
  __memalign_hook = old_memalign_hook;
  fprintf(logFile,"Checking for allocated memory on %d mallocs and %d free...\n", all_count, free_count);
  
  // FILE *logFile = fopen("logFile.txt", "w");
  if(count-START_MALLOC>=MAX_MALLOCS)
    count=MAX_MALLOCS-1+START_MALLOC;
  for (int i = 1; i<count-START_MALLOC; i++){
      if (sizes[i] != -100){
          // printf("Checking for allocated memory... %ld \n", sizes[i]);
          // printf("ERROR : Memory not freed \n");
          fprintf(logFile,"ERROR : Memory not freed at address %p (index %d) size %ld allocated at %p \n", 
                  original_address[i],i, sizes[i], return_address[i]);
      }
  }
  free(original_address);
  free(return_address);
  fclose(logFile);
}
