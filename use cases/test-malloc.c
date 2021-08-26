#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

int main(int argc, char* argv[]) {
    /**
    int *m1 = malloc(8*sizeof(int));
    m1[1] = 2;
    int *m2 = realloc(m1,6*sizeof(int));
    free(m2);
    printf("PID:%ld",(long)getpid());
    **/
   
   for(int i=0;i<10;i++){
       int *m3 = malloc(16*sizeof(int));
       //m3 = realloc(m3,32*sizeof(int));
       free(m3);
       printf("PID:%ld",(long)getpid());
   }

}
