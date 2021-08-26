#ifndef COMPILE_PATCH_H
#define COMPILE_PATCH_H

struct inferior;
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

/* Handle the input from the 'patch where' command.  The
   "patch where" command is used to print the address of the next
   possible insertion from the address given as argument.  */

extern void compile_patch_where_command(const char *arg, int from_tty);

extern void compile_patch_dw_command(const char *arg, int from_tty);

/* Handle the input from the 'patch goto' command.  The
   "patch goto" command is used to replace an instruction with a jump
   to a specified location.  */

extern void compile_patch_goto_command(const char *arg, int from_tty);

/* Handle the input from the 'patch list' command.  The
   "patch list" command is used to display all active patches in 
   the inferior.  */

extern void compile_patch_list_command(const char *arg, int from_tty);

/* Handle the input from the 'patch delete' command.  The
   "patch delete" command is used to remove a patch from the inferior.
   It expects an index as argument.  */

extern void compile_patch_delete_command(const char *arg, int from_tty);

/* Handle the input from the 'patch store' command.  The
   "patch store" command is used to store patch data to a file when 
   detaching from a running process.  */

extern void compile_patch_store_command(const char *arg, int from_tty);

/* Handle the input from the 'patch load' command.  The
   "patch load" is used to load patch data from a file when attaching
   to a process that has been previously patched.  */

extern void compile_patch_load_command(const char *arg, int from_tty);

extern void patch_sigill_handler(const char *arg, int from_tty);

/* Resets static data on inferior exit.  */

extern void reset_patch_data (struct inferior *inf);
#endif /* COMPILE_PATCH_H */
