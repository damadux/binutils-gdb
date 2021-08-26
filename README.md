This repository is for easy deployment of Paul Naert's GDB patch with the necessary scripts/libraries.

Here are the steps to set up the environment:

1. Switch the GCC environment to GCC 9.0 (e.g. using update-alternative on Ubuntu)

2. Compile the gdb patch (gdb-patch/gdb) in another directory using GCC 9
        mkdir GDB-8-NP
        cd GDB-8-NP
        ../gdb-patch/gdb/configure
        make install
        
3. If needed, switch the GDB envionment to this version (e.g. using update-alternative on Ubuntu)

4. Compile dwhooks-clean.c into the library libdw.so
        gcc -c -Wall -fPIC dwhoos-clean.c -o dwhooks-clean.o
        gcc dwhooks-clean.o -shared -o libdw.so
        
5. Compile the LD_PRELOAD source file into its library libpreload.so
        gcc -Wall -fPIC -DPIC -c preload.c
        gcc -shared preload.o -ldl -L. -ldw -o libpreload.so

        


