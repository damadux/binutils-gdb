This repository is for easy deployment of Paul Naert's GDB patch with the necessary scripts/libraries.

Here are the steps to set up the environment (on Ubuntu 18.04):

Requirements to build gdb (on ubuntu 18.04): 

- texinfo
- bison
- flex
- gcc 
- gmp (libgmp3-dev)


1. Create a separate directory to compile GDB:

        mkdir config
        cd config

2. Run the configure script. Use the --prefix option to install the program under a specific directory. 

        ../gdb-patch/gdb/configure --prefix=/usr/local/gdb-pn

3. Compile using make, then make install

        make
        make install

If you have another version of gdb already installed. You can consider using update-alternative to freely switch GDB's version

4. Compile dwhooks-clean.c into the library libdw.so

        gcc -c -Wall -fPIC dwhooks-clean.c -o dwhooks-clean.o
        gcc dwhooks-clean.o -shared -o libdw.so

5. Fix file links in dw.gdb to match the one of your setup

6. Compile one of the examples (for example here double-free)

        gcc -Wall -Wextra -g -o bug-dbl-free a.c -ldl

7. Launch it with gdb (this custom version) from the "source" directory

        gdb ../use-cases/craft-dbl-free/bug-dbl-free

8. Insert breakpoints, watchpoints as needed

9. Start the execution by running the "dw.gdb" file

        (gdb) source dw.gdb 

        


        


