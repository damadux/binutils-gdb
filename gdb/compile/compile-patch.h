#ifndef COMPILE_PATCH_H
#define COMPILE_PATCH_H

/* Handle the input from the 'patch code' command.  The
   "patch code" command is used to patch in the code an expression
   containing calls to the GCC compiler.  The language expected in this
   command is the language currently set in GDB. */

extern void compile_patch_code_command(const char *arg, int from_tty);

/* Handle the input from the 'patch file' command.  The
   "patch file" command is used to patch in the code an expression
   containing calls to the GCC compiler. It takes as argument 
   a source file.  The language expected in this command
   is the language currently set in GDB. */

extern void compile_patch_file_command(const char *arg, int from_tty);

/* The patch command without a suffix is interpreted as patch code. */

extern void compile_patch_command(const char *arg, int from_tty);

#endif /* COMPILE_PATCH_H */
