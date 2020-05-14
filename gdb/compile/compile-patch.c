#include "defs.h"
#include "gdbcmd.h"
#include "arch-utils.h"
#include "gdbsupport/gdb_unlinker.h"
#include "gdbsupport/pathstuff.h"
#include "linespec.h"
#include "objfiles.h"
#include "compile.h"
#include "compile-object-load.h"
#include "observable.h"
#include <map>

#define PAGE_SIZE sysconf (_SC_PAGE_SIZE)
#define PAGE_ADDRESS(addr) (addr / PAGE_SIZE) * PAGE_SIZE
#define TP_MAX_SIZE 0x100

/* Hold "patch" commands.  */

static struct cmd_list_element *compile_patch_command_list;

/* Finds the return address for a trampoline placed at insn_addr.  */
static CORE_ADDR
find_return_address (struct gdbarch *gdbarch, CORE_ADDR insn_addr, bool verbose)
{
  /* In this version, we only check if we have enough room to put a jump.  */
  if (gdb_insn_length (gdbarch, insn_addr)
      < gdbarch_jmp_insn_length (gdbarch, 0))
    {
      return 0;
    }
  CORE_ADDR return_address = insn_addr + gdb_insn_length (gdbarch, insn_addr);
  return return_address;
}

/* Is the page containing addr available ? If so map it.  */
static CORE_ADDR
try_map_page (gdbarch *gdbarch, CORE_ADDR trampoline_addr, int trampoline_size)
{
  int page_size = PAGE_SIZE;
  const int prot
    = GDB_MMAP_PROT_READ | GDB_MMAP_PROT_WRITE | GDB_MMAP_PROT_EXEC;

  CORE_ADDR mapped_page
    = gdbarch_infcall_mmap (gdbarch, trampoline_addr, 1, prot);

  if (mapped_page != PAGE_ADDRESS (trampoline_addr))
    {
      gdbarch_infcall_munmap (gdbarch, mapped_page, page_size);
      return (CORE_ADDR) 0;
    }
  /* Check if the trampoline overlaps several pages.  */
  if (mapped_page + page_size < trampoline_addr + trampoline_size)
    {
      CORE_ADDR second_page
	= gdbarch_infcall_mmap (gdbarch, mapped_page + page_size, page_size,
				prot);
      if (second_page == mapped_page + page_size)
	{
	  return mapped_page;
	}
      else
	{
	  gdbarch_infcall_munmap (gdbarch, mapped_page, page_size);
	  gdbarch_infcall_munmap (gdbarch, second_page, page_size);
	  return (CORE_ADDR) 0;
	}
    }
  return mapped_page;
}

/* This function aims to find the next available chunk of memory around
   insn_address where we have enough room to put a trampoline of size
   trampoline_size. It keeps a map pointing to the next available portion of
   memory given a minimum address.  */
static CORE_ADDR
allocate_trampoline (gdbarch *gdbarch, CORE_ADDR insn_address,
		     int trampoline_size)
{
  int max_pages_searched = 100;
  int page_size = PAGE_SIZE;
  static std::map<CORE_ADDR, CORE_ADDR> current_stack_top;

  /* We do not handle the case where the trampoline is larger than a page.  */
  gdb_assert (trampoline_size < page_size);

  /* Return value.  */
  int bit_shift = gdbarch_jmp_insn_length (gdbarch, 1) * 8 - 3;

  CORE_ADDR trampoline_address
    = ((insn_address >> bit_shift) > 0
	 ? (((insn_address >> bit_shift) - 1) << bit_shift)
	 : 100 * PAGE_SIZE);

  if (current_stack_top.find (trampoline_address) != current_stack_top.end ())
    {
      trampoline_address = current_stack_top[trampoline_address];
      CORE_ADDR next_page = PAGE_ADDRESS (trampoline_address) + page_size;
      CORE_ADDR trampoline_end = trampoline_address + trampoline_size;
      if (trampoline_end <= next_page)
	{
	  current_stack_top[trampoline_address] = trampoline_end;
	  return trampoline_address;
	}
      /* We don't have enought room to put all of the trampoline
	on this page but the next one is available.  */
      if (try_map_page (gdbarch, next_page, 0) != 0)
	{
	  current_stack_top[trampoline_address] = trampoline_end;
	  return trampoline_address;
	}
    }

  for (int i = 0; i < max_pages_searched; i++)
    {
      if (try_map_page (gdbarch, trampoline_address, trampoline_size) != 0)
	{
	  current_stack_top[trampoline_address]
	    = trampoline_address + trampoline_size;
	  return trampoline_address;
	}
      trampoline_address = PAGE_ADDRESS (trampoline_address + page_size);
    }

  return 0;
}

static CORE_ADDR
build_compile_trampoline (struct gdbarch *gdbarch,
			  struct compile_module *module, CORE_ADDR insn_addr,
			  CORE_ADDR return_address)
{
  /* Allocate memory for the trampoline in the inferior.  */
  CORE_ADDR trampoline = allocate_trampoline (gdbarch, insn_addr, TP_MAX_SIZE);

  if (trampoline == 0)
    {
      return 0;
    }

  /* Build trampoline.  */
  gdb_byte trampoline_instr[TP_MAX_SIZE];
  int trampoline_size
    = gdbarch_fill_trampoline_buffer (gdbarch, trampoline_instr, module);

  gdb_assert (trampoline_size < TP_MAX_SIZE);

  /* Copy content of trampoline_instr to inferior memory.  */
  target_write_memory (trampoline, trampoline_instr, trampoline_size);

  /* Relocate replaced instruction */
  CORE_ADDR trampoline_end = trampoline + trampoline_size;

  gdbarch_relocate_instruction (gdbarch, &trampoline_end, insn_addr);

  gdb_assert (trampoline_end - trampoline + gdbarch_jmp_insn_length (gdbarch, 0)
	      < TP_MAX_SIZE);

  /* Jump back to return address.  */
  gdbarch_patch_jump (gdbarch, trampoline_end, return_address);

  return trampoline;
}

/* Convert a string describing a location to an instruction address.
   Here we assume the location to correspond to only one pc. */
static CORE_ADDR
location_to_pc (const char *location)
{
  struct linespec_result canonical;

  event_location_up event_location
    = string_to_event_location (&location, current_language);
  create_sals_from_location_default (event_location.get (), &canonical,
				     bp_breakpoint);
  CORE_ADDR addr = canonical.lsals[0].sals[0].pc;
  return addr;
}

/* The central function for the patch command. */
static void
patch_code (const char *location, const char *code)
{
  struct gdbarch *gdbarch = target_gdbarch ();

  /* Convert location string to an instruction address.  */
  CORE_ADDR insn_addr = location_to_pc (location);

  /* Compile code.  */
  enum compile_i_scope_types scope = COMPILE_I_PATCH_SCOPE;
  compile_file_names fnames = compile_to_object (NULL, code, scope, insn_addr);
  gdb::unlinker object_remover (fnames.object_file ());
  gdb::unlinker source_remover (fnames.source_file ());

  /* Load compiled code into memory.  */
  struct compile_module *compile_module
    = compile_object_load (fnames, scope, NULL);

  /* Build a trampoline which calls the compiled code.  */
  CORE_ADDR return_address = find_return_address (gdbarch, insn_addr, true);

  if (return_address != 0)
    {
      CORE_ADDR trampoline_address
	= build_compile_trampoline (gdbarch, compile_module, insn_addr,
				    return_address);

      if (trampoline_address == 0)
	{
	  fprintf_filtered (gdb_stderr, "Unable to build a trampoline.\n");
    unlink (compile_module->source_file);
    xfree (compile_module->source_file);
    unlink (objfile_name (compile_module->objfile));
    xfree (compile_module);
    return;
	}

      /* Patch in the jump to the trampoline.  */
      bool success
	= gdbarch_patch_jump (gdbarch, insn_addr, trampoline_address);
      if (!success)
	{
	  fprintf_filtered (gdb_stderr,
			    "Unable to insert the code at the given location.\n\
Make sure the instruction is long enough \n\
to be replaced by a jump instruction.\n");
	}
    }
  /* Free unused memory */
  /* Some memory is left allocated in the inferior because
     we still need to access it to execute the compiled code.  */
  unlink (compile_module->source_file);
  xfree (compile_module->source_file);
  unlink (objfile_name (compile_module->objfile));
  xfree (compile_module);
}

/* Handle the input from the 'patch code' command.  The
   "patch code" command is used to patch in the code an expression
   containing calls to the GCC compiler.  The language expected in this
   command is the language currently set in GDB.  */
static void
compile_patch_code_command (const char *arg, int from_tty)
{
  if (arg == NULL)
    {
      error ("No arguments were entered for the patch code command.");
    }
  char *dup = strdup (arg);
  const char *location = strtok (dup, " ");
  const char *code = strtok (NULL, "\0");
  if (code == NULL)
    {
      free (dup);
      error ("Missing the code argument for the patch code command.");
    }
  patch_code (location, code);
  free (dup);
}

/* Handle the input from the 'patch file' command.  The
   "patch file" command is used to patch in the code an expression
   containing calls to the GCC compiler. It takes as argument
   a source file.  The language expected in this command
   is the language currently set in GDB. */
static void
compile_patch_file_command (const char *arg, int from_tty)
{
  if (arg == NULL)
    {
      error ("No arguments were entered for the patch file command.");
    }
  char *dup = strdup (arg);
  const char *location = strtok (dup, " ");
  const char *source_file = strtok (NULL, " ");
  if (source_file == NULL)
    {
      free (dup);
      error ("Missing the second argument for the patch file command.");
    }
  gdb::unique_xmalloc_ptr<char> abspath = gdb_abspath (source_file);
  std::string code_buf = string_printf ("#include \"%s\"\n", abspath.get ());
  patch_code (location, code_buf.c_str ());
  free (dup);
}

/* The patch command without a suffix is interpreted as patch code.  */
static void
compile_patch_command (const char *arg, int from_tty)
{
  compile_patch_code_command (arg, from_tty);
}

void _initialize_compile_patch();
static void
_initialize_compile_patch (void)
{
  struct cmd_list_element *c = NULL;

  compile_cmd_element
    = add_prefix_cmd ("patch", class_obscure, compile_patch_command, _ ("\
Command to compile source code and patch it into the inferior."),
		      &compile_patch_command_list, "patch ", 1, &cmdlist);

  add_cmd ("code", class_obscure, compile_patch_code_command, _ ("\
Compile, and patch code at location.\n\
\n\
Usage: patch code [LOCATION] [CODE]\n\
\n\
The source code may be specified as a simple one line expression, e.g.:\n\
\n\
    patch code main:2 printf(\"Hello world\\n\");\n\
\n\
It will be executed each time the instruction at location is hit."),
	   &compile_patch_command_list);

  c = add_cmd ("file", class_obscure, compile_patch_file_command, _ ("\
Compile and patch in a file containing source code.\n\
\n\
Usage: compile patch file [LOCATION] [FILENAME]"),
	       &compile_patch_command_list);
  set_cmd_completer (c, filename_completer);
}
