/* Compile and patch module

   Copyright (C) 2014-2019 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "arch-utils.h"
#include "block.h"
#include "breakpoint.h"
#include "gdbsupport/gdb_unlinker.h"
#include "gdbsupport/pathstuff.h"
#include "linespec.h"
#include "objfiles.h"
#include "source.h"
#include "compile-internal.h"
#include "compile.h"
#include "compile-object-load.h"
#include "observable.h"
#include "patch.h"
#include <map>

#define JMP_INSN_LENGTH 5
#define PAGE_SIZE 0x1000
#define TP_SIZE 0x100
#define PAGE_ADDRESS(a) ((a/PAGE_SIZE) * PAGE_SIZE)
#define MINIMUM_ADDRESS(a) ((a>>29) > 0 ? (((a>>29) -1)<<29) : 0x100000)
PatchVector all_patches;

/* Finds the return address for a trampoline placed at insn_addr.  */
static CORE_ADDR
find_return_address (struct gdbarch *gdbarch, CORE_ADDR insn_addr,
                     bool verbose)
{
  /* In this version, we only check if we have enough room to put a jump.  */
  if (gdb_insn_length (gdbarch, insn_addr) < JMP_INSN_LENGTH)
    {
      return 0;
    }
  CORE_ADDR return_address
      = insn_addr + gdb_insn_length (gdbarch, insn_addr);
  return return_address;
}

/* Is the page containing addr available ? If so map it.  */
static CORE_ADDR
can_mmap(gdbarch *gdbarch, CORE_ADDR addr, int trampoline_size)
{
  const int prot = GDB_MMAP_PROT_READ | GDB_MMAP_PROT_WRITE | GDB_MMAP_PROT_EXEC;
  
  CORE_ADDR mmapped_area = gdbarch_infcall_mmap(gdbarch, addr, PAGE_SIZE, prot);
  
  if(mmapped_area <= addr && mmapped_area + PAGE_SIZE > addr)
  {
    /* The trampoline overlaps several pages */
    if(mmapped_area + PAGE_SIZE < addr + trampoline_size)
    {
      CORE_ADDR second_mmap = gdbarch_infcall_mmap(gdbarch, mmapped_area + PAGE_SIZE, PAGE_SIZE, prot);
      if(second_mmap == mmapped_area + PAGE_SIZE)
      {
        return mmapped_area;
      }
      else
      {
        gdbarch_infcall_munmap(gdbarch, mmapped_area, PAGE_SIZE);
        gdbarch_infcall_munmap(gdbarch, second_mmap, PAGE_SIZE);
        return (CORE_ADDR) 0;
      }
    }
    return mmapped_area;
  }
  gdbarch_infcall_munmap(gdbarch, mmapped_area, PAGE_SIZE);
  return (CORE_ADDR) 0;
}

/* This function aims to find the next available chunk of memory from min_tp_address
   where we have enough room to put a trampoline of size trampoline_size.
   It keeps a map pointing to the next available portion of memory given a minimum address.  */
static CORE_ADDR
try_put_trampoline(gdbarch *gdbarch, CORE_ADDR min_tp_address, int trampoline_size)
{
  int max_pages_searched = 100;
  static std::map<CORE_ADDR, CORE_ADDR> current_stack_top;
  
  /* We do not handle the case where the trampoline is larger than a page.  */
  gdb_assert(trampoline_size < PAGE_SIZE);

  /* Return value.  */
  CORE_ADDR tp_address = min_tp_address;

  if(current_stack_top.find(tp_address) != current_stack_top.end())
  {
    tp_address = current_stack_top[tp_address];
    CORE_ADDR next_page = PAGE_ADDRESS(tp_address)+PAGE_SIZE;
    CORE_ADDR tp_end = tp_address + trampoline_size;
    if(tp_end <= next_page)
    {
      current_stack_top[tp_address] = tp_end;
      return tp_address;
    }
    /* We don't have enought room to put all of the trampoline 
      on this page but the next one is available.  */
    if(can_mmap(gdbarch, next_page, 0) != 0)
    {
      current_stack_top[tp_address] = tp_end;
      return tp_address;
    }
  }

  for(int i = 0; i<max_pages_searched; i++)
  {
    if(can_mmap(gdbarch, tp_address, trampoline_size) != 0)
    {
      current_stack_top[tp_address] = tp_address + trampoline_size;
      return tp_address;
    }
    tp_address = PAGE_ADDRESS(tp_address + PAGE_SIZE);
  }

  return 0;
}

/* Allocate some space for a trampoline.  */
static CORE_ADDR
allocate_trampoline (struct gdbarch *gdbarch, CORE_ADDR addr, int size)
{
  CORE_ADDR min_tp_address = MINIMUM_ADDRESS(addr);
  return try_put_trampoline(gdbarch, min_tp_address, size);
}

static CORE_ADDR
build_compile_trampoline (struct gdbarch *gdbarch,
                          struct compile_module *module, Patch *patch,
                          CORE_ADDR return_address)
{
  CORE_ADDR insn_addr = patch->address;
  struct symbol *func_sym = module->func_sym;
  CORE_ADDR func_addr = BLOCK_ENTRY_PC (SYMBOL_BLOCK_VALUE (func_sym));

  CORE_ADDR regs_addr = module->regs_addr;

  /* Build trampoline.  */
  gdb_byte trampoline_instr[TP_SIZE];
  int trampoline_size
      = gdbarch_fill_trampoline (gdbarch, trampoline_instr, func_addr, regs_addr);
  
  gdb_assert(trampoline_size<TP_SIZE);
  
  /* Allocate memory for the trampoline in the inferior.  */
  CORE_ADDR trampoline
      = allocate_trampoline (gdbarch, insn_addr, sizeof (trampoline_instr));
  
  if (trampoline != 0)
  {
    /* Copy content of trampoline_instr to inferior memory.  */
    target_write_memory (trampoline, trampoline_instr, trampoline_size);

    /* Relocate replaced instruction */
    CORE_ADDR trampoline_end = trampoline + trampoline_size;

    gdbarch_relocate_instruction (gdbarch, &trampoline_end, insn_addr);

    /* Jump back to return address.  */
    gdbarch_patch_jump(gdbarch, trampoline_end, return_address, 0);

    gdb_assert(trampoline_end - trampoline < TP_SIZE);
  }

  return trampoline;
}

/* Convert a string describing a location to an instruction address. */
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
  CORE_ADDR addr = location_to_pc (location);

  /* Compile code.  */
  enum compile_i_scope_types scope = COMPILE_I_SIMPLE_SCOPE;
  compile_file_names fnames = compile_to_object (NULL, code, scope, addr);
  gdb::unlinker object_remover (fnames.object_file ());
  gdb::unlinker source_remover (fnames.source_file ());
  /* Load compiled code into memory.  */
  struct compile_module *compile_module
      = compile_object_load (fnames, scope, NULL);

  /* Build a trampoline which calls the compiled code.  */
  CORE_ADDR return_address = find_return_address (gdbarch, addr, true);
  if (return_address != 0)
  {
    Patch *patch = new Patch (compile_module->munmap_list_head, addr);

    CORE_ADDR trampoline_address = build_compile_trampoline (
        gdbarch, compile_module, patch, return_address);

    patch->trampoline_address = trampoline_address;

    /* Patch in the jump to the trampoline.  */
    if (trampoline_address != 0
        && gdbarch_patch_jump (gdbarch, addr, trampoline_address, 1) == 0)
      {
        all_patches.add (patch);
      }
    else
      {
        fprintf_filtered(gdb_stdlog,
"Unable to insert the code at the given location.\n\
Make sure the instruction is long enough.\n");
        delete patch;
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
void
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
void
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
      error ("Missing the second argument for the patch code command.");
    }
  gdb::unique_xmalloc_ptr<char> abspath = gdb_abspath (source_file);
  std::string code_buf
      = string_printf ("#include \"%s\"\n", abspath.get ());
  patch_code (location, code_buf.c_str ());
  free (dup);
}

/* The patch command without a suffix is interpreted as patch code.  */
void
compile_patch_command (const char *arg, int from_tty)
{
  compile_patch_code_command (arg, from_tty);
}

/* Called on inferior exit. We reset everything.  */
static void
reset_patch_data (struct inferior *inferior)
{
  /* Reset the mmap values for trampolines.  */
  // TODO
  /* Delete all live patches objects.  */
  all_patches.reset();
}

void
_initialize_compile_patch (void)
{
  gdb::observers::inferior_exit.attach(reset_patch_data);
}