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
#include "common/gdb_unlinker.h"
#include "common/pathstuff.h"
#include "linespec.h"
#include "objfiles.h"
#include "source.h"
#include "compile-internal.h"
#include "compile.h"
#include "compile-object-load.h"
#include "patch.h"
#include "cli/cli-utils.h"

PatchVector all_patches;

/* Fills the trampoline but does not relocate the replaced instruction */
int
fill_trampoline (unsigned char *trampoline_instr, CORE_ADDR called,
                 CORE_ADDR arg_regs)
{

  int i = 0;
  /* save registers */
  trampoline_instr[i++] = 0x54; /* push %rsp */
  trampoline_instr[i++] = 0x55; /* push %rbp */
  trampoline_instr[i++] = 0x57; /* push %rdi */
  trampoline_instr[i++] = 0x56; /* push %rsi */
  trampoline_instr[i++] = 0x52; /* push %rdx */
  trampoline_instr[i++] = 0x51; /* push %rcx */
  trampoline_instr[i++] = 0x53; /* push %rbx */
  trampoline_instr[i++] = 0x50; /* push %rax */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x57; /* push %r15 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x56; /* push %r14 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x55; /* push %r13 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x54; /* push %r12 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x53; /* push %r11 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x52; /* push %r10 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x51; /* push %r9 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x50; /* push %r8 */
  /* may cause bug when stepped over */
  trampoline_instr[i++] = 0x9c; /* pushfq */ 
      

  /* provide gdb_expr () arguments */
  trampoline_instr[i++] = 0x48; /* movabs <arg>,%rdi */
  trampoline_instr[i++] = 0xbf;
  memcpy (trampoline_instr + i, &arg_regs, 8);
  i += 8;
  trampoline_instr[i++] = 0x48; /* mov %rbp, (%rdi) */
  trampoline_instr[i++] = 0x89;
  trampoline_instr[i++] = 0x2f;

  /* call gdb_expr () */
  trampoline_instr[i++] = 0x48; /* movabs <called>,%rax */
  trampoline_instr[i++] = 0xb8;
  memcpy (trampoline_instr + i, &called, 8);
  i += 8;
  trampoline_instr[i++] = 0xff; /* callq *%rax */
  trampoline_instr[i++] = 0xd0;

  /* restore registers */
  trampoline_instr[i++] = 0x9d; /* popfq */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x58; /* pop %r8 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x59; /* pop %r9 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x5a; /* pop %r10 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x5b; /* pop %r11 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x5c; /* pop %r12 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x5d; /* pop %r13 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x5e; /* pop %r14 */
  trampoline_instr[i++] = 0x41;
  trampoline_instr[i++] = 0x5f; /* pop %r15 */
  trampoline_instr[i++] = 0x58; /* pop %rax */
  trampoline_instr[i++] = 0x5b; /* pop %rbx */
  trampoline_instr[i++] = 0x59; /* pop %rcx */
  trampoline_instr[i++] = 0x5a; /* pop %rdx */
  trampoline_instr[i++] = 0x5e; /* pop %rsi */
  trampoline_instr[i++] = 0x5f; /* pop %rdi */
  trampoline_instr[i++] = 0x5d; /* pop %rbp */
  trampoline_instr[i++] = 0x5c; /* pop %rsp */

  return i;
}

CORE_ADDR
find_return_address (struct gdbarch *gdbarch, CORE_ADDR *insn_addr,
                     bool verbose)
{
  /* For now we only find the next 5 byte instruction in the code.
     In the future, we can implement better techniques to replace
     smaller instructions.  */
  if (gdb_insn_length (gdbarch, *insn_addr) < 5)
    {
      CORE_ADDR corrected_address = *insn_addr;
      string_file buf;
      while (gdb_insn_length (gdbarch, corrected_address) < 5)
        {
          gdb_print_insn (gdbarch, corrected_address, &buf, NULL);
          if (strstr (buf.c_str (), "ret") != NULL)
            {
              /* we don't stop the program execution with an error,
              in order to free the allocated memory */
              fprintf_filtered (
                  gdb_stderr,
                  "May not patch code at %s or before the end "
                  "of the function.\n",
                  paddress (gdbarch, *insn_addr));
              *insn_addr = (CORE_ADDR)0;
              return (CORE_ADDR)0;
            }
          buf.clear ();
          corrected_address
              += gdb_insn_length (gdbarch, corrected_address);
        }
      struct symtab_and_line sal = find_pc_sect_line (
          corrected_address, find_pc_section (corrected_address), 0);
      if (verbose
          && !yquery (
              _("Instruction at address 0x%lx is not 5 bytes long, "
                 "place code at address 0x%lx (file %s line %d) ? \n"),
              *insn_addr, corrected_address,
              symtab_to_filename_for_display (sal.symtab), sal.line))
        {
          fprintf_filtered (gdb_stderr,
                            "May not patch a jump at %s\n",
                            paddress (gdbarch, *insn_addr));
          *insn_addr = (CORE_ADDR)0;
          return (CORE_ADDR)0;
        }
      *insn_addr = corrected_address;
    }
  CORE_ADDR return_address
      = *insn_addr + gdb_insn_length (gdbarch, *insn_addr);
  return return_address;
}



CORE_ADDR
find_return_address_amad3 (struct gdbarch *gdbarch, CORE_ADDR *insn_addr,
                     CORE_ADDR *tp_address, bool verbose)
{
  /* In this implementation we try to make it possible to instrument
    short (<5 bytes) instructions. In order to do that we replace the 
    first byte of the instrumented instruction with a jump (e9) instruction.
    Then we consider the beginning of the next instruction to be part of the
    jump offset. i e if we want to insert a jump on I1:
        I1 I1 I1 I2 I2 ...  
    ->  E9 XX XX I2 I2 ...
    And we try and find the XX XX so that the jump points to an available
    address where we put the jump pad. */

    /* If we don't find it using those bytes, we can try to modify the next one too
        E9 XX XX E9 XX ... */

  /* Find length of first instruction */
  // int insn_length = gdb_insn_length(gdbarch, *insn_addr);
  // /* Scan memory to find where to place jump */
  // switch(insn_length)
  // {
  //   case 1:
  //   case 2:
  //   case 3:
  //   /* The range here is 65K */
  //         tp_address = allocate_trampoline_close(gdbarch,0x80);
  //   case 4:
  //   /* We have a range of 16M so we check if we can access the default trampoline position */
  //     tp_address = allocate_trampoline(gdbarch, 0x80); // size hardcoded !
  //     int64_t long_jump_offset = tp_address - insn_address - 0x5;
  //     if (long_jump_offset > INT_MAX || long_jump_offset < INT_MIN)
  //       {
  //         tp_address = allocate_trampoline_close(gdbarch,0x80);
  //       }
  //     break;
  //   default:
  //     tp_address = allocate_trampoline(gdbarch, 0x80);
  //     break;
  // }
  CORE_ADDR return_address
          = *insn_addr + gdb_insn_length (gdbarch, *insn_addr);
  while (return_address < *insn_addr + 5)
  {
    return_address+=gdb_insn_length (gdbarch, return_address);
  }
  return return_address;
  
}

/* Allocate some space for a trampoline.
   mmap is done one page at a time, 
   a larger trampoline cannot be allocated.  */
CORE_ADDR
allocate_trampoline (struct gdbarch *gdbarch, int size, CORE_ADDR addr, int sigill_idx)
{
  const int page_size = 0x1000;
  static CORE_ADDR trampoline_mmap_address = 0x100000;
  static CORE_ADDR trampoline_address = 0;
  const unsigned prot
      = GDB_MMAP_PROT_READ | GDB_MMAP_PROT_WRITE | GDB_MMAP_PROT_EXEC;

  /* On inferior exit, reset the static variables. */
  if (size < 0)
    {
      trampoline_address = 0;
      trampoline_mmap_address = 0x100000;
      return 0;
    }

  int32_t difference = 0;
  /* Initialize tp address */
  if (trampoline_address == 0)
    {
      /* Allocate a new chunk of memory of one page*/ 
      trampoline_address = gdbarch_infcall_mmap (
          gdbarch, trampoline_mmap_address, page_size, prot);
      trampoline_mmap_address = trampoline_address;
    }
  else
  {
    trampoline_address += size;
  }
  

  if (sigill_idx != 0 && sigill_idx < 4)
  {
    int32_t offset = 0x6<<(8*(sigill_idx - 1));
    int64_t pre_offset = trampoline_address - addr - 5;
    if (pre_offset > INT_MAX || pre_offset < INT_MIN)
    {
      fprintf_filtered (
          gdb_stderr,
          "E.Jump pad too far from instruction for jump back (offset 0x%" PRIx64
          " > int32). \n",
          pre_offset);
      return 0;
    }
    int32_t pre_offset32 = (int32_t) pre_offset;
    // printf("address %lx pre_offset %x \n", trampoline_address, (unsigned int) pre_offset32);

    for(int i = 0; i<4; i++)
    {
      if(i+1 != sigill_idx)
      {
        memcpy( ((gdb_byte *) &offset) + i, ((gdb_byte *) &pre_offset32) + i, 1);
      }
    }
    // printf("offset %x pre_offset %x \n", (unsigned int) offset, (unsigned int) pre_offset32);

    difference = offset - pre_offset32;
    // printf("difference %x \n", difference);
    if(difference < 0)
    {
      difference += 0x1<<(8*sigill_idx);
      offset += 0x1<<(8*sigill_idx);
    }
    // printf("difference %x offset %x \n", (unsigned int) difference, (unsigned int) offset);

    int skip_pages = (difference + trampoline_address - trampoline_mmap_address) / page_size;
    if(skip_pages > 0)
    {
      trampoline_address = 0;
      trampoline_mmap_address += (skip_pages-1)*page_size;
    }
  }
  if (trampoline_address == 0
      || trampoline_address + size > trampoline_mmap_address)
    {
      /* Allocate a new chunk of memory of one page*/ /* FIXME the position */
      trampoline_mmap_address+=page_size;
      trampoline_address = gdbarch_infcall_mmap (
          gdbarch, trampoline_mmap_address, page_size, prot);
      trampoline_mmap_address = trampoline_address;
      trampoline_address += (difference + trampoline_address - trampoline_mmap_address) % page_size;
    }
  else
    {
      trampoline_address += difference % page_size;
    }
  // printf("address %lx difference %x \n", trampoline_address, (unsigned int) difference);
  return trampoline_address;
}

/* Is this page available ? If so map it */
CORE_ADDR
mmappable(gdbarch *gdbarch, CORE_ADDR addr)
{
  const int prot = 7;
  const int trampoline_size = 0x100;
  const int page_size = 0x1000;
  CORE_ADDR mmapped_area = gdbarch_infcall_mmap(gdbarch, addr, trampoline_size, prot);
  if(mmapped_area + page_size > addr+trampoline_size && mmapped_area <= addr)
  {
    return mmapped_area;
  }
  else
  {
    gdbarch_infcall_munmap(gdbarch,addr,page_size);
    return (CORE_ADDR) 0;
  }
}


/* Choose where to put the trampoline */
CORE_ADDR
place_trampoline(gdbarch *gdbarch, CORE_ADDR addr, int lengths[])
{
  const gdb_byte ill_insns[14] = {6, 7, 14, 22, 23, 30, 31, 39, 47, 55, 63, 96, 97, 98};
  int last_insn_index = 0; // between 1 and 4
  for(int i = 0; i<5; i++)
  {
    if(lengths[4-i] > 0)
    {
      last_insn_index = 4-i;
      break;
    }
  }
  if(lengths[4] > 0) // insn beginning on 5th byte
  {
    int32_t offset = 0;
    target_read_memory(addr+1,((gdb_byte *)&offset),3);
    for( int idx = 0; idx< 14; idx++)
    {
      memcpy(((gdb_byte *)&offset)+3,&ill_insns[idx],1);
      CORE_ADDR tp_address = addr+offset+5;
      // Not unmappable, TODO : make it cleanable
      if (mmappable(gdbarch,tp_address))
      {
        return tp_address;
      }
    }
    error(_("No suitable destination for tp"));
  }
  else
  {

    CORE_ADDR tp_address = allocate_trampoline(gdbarch, 0x100, addr, last_insn_index);
    // printf("tp address %lx offset %lx \n", tp_address, tp_address - addr - 5);
    return tp_address;
  }
  

  error(_("No insn on final byte"));
  return (CORE_ADDR) 0;
}


/* Analyze the layout */
CORE_ADDR
analyse_layout(gdbarch *gdbarch, CORE_ADDR addr)
{
  CORE_ADDR current_address = addr;
  int insn_length;
  gdb_byte instructions[30];
  int lengths[5]={0,0,0,0,0};
  while (current_address < addr +5)
  {
    insn_length = gdb_insn_length(gdbarch, current_address);
    lengths[(int)(current_address - addr)] = insn_length;
    current_address += insn_length;
  }
  target_read_memory(addr, instructions, (int) (current_address - addr));

  return place_trampoline(gdbarch, addr, lengths);
}


CORE_ADDR custom_trampoline(struct gdbarch *gdbarch, CORE_ADDR insn_address, int size)
{
  if(gdb_insn_length(gdbarch,insn_address)>=5)
  {
    return allocate_trampoline(gdbarch,size, 0, 0);
  }
  
  return analyse_layout(gdbarch, insn_address);
}

// CORE_ADDR
// allocate_trampoline_close (struct gdbarch *gdbarch, int size)
// {
//   const int page_size = 0x1000;
//   static CORE_ADDR trampoline_mmap_address = 0x391000;
//   static CORE_ADDR trampoline_address = 0;
//   const unsigned prot
//       = GDB_MMAP_PROT_READ | GDB_MMAP_PROT_WRITE | GDB_MMAP_PROT_EXEC;

//   /* On inferior exit, reset the static variables. */
//   if (size < 0)
//     {
//       trampoline_address = 0;
//       trampoline_mmap_address = 0x100000;
//       return 0;
//     }

//   gdb_assert (size <= page_size);
//   if (trampoline_address == 0
//       || trampoline_address + 2*size > trampoline_mmap_address)
//     {
//       /* Allocate a new chunk of memory of one page*/
//       trampoline_address = gdbarch_infcall_mmap (
//           gdbarch, trampoline_mmap_address, page_size, prot);
//       trampoline_mmap_address += page_size;
//     }
//   else
//     {
//       trampoline_address += size;
//     }
//   return trampoline_address;
// }





CORE_ADDR
build_compile_trampoline (struct gdbarch *gdbarch,
                          struct compile_module *module, Patch *patch,
                          CORE_ADDR return_address)
{
  CORE_ADDR insn_addr = patch->address;
  struct symbol *func_sym = module->func_sym;
  CORE_ADDR func_addr = BLOCK_ENTRY_PC (SYMBOL_BLOCK_VALUE (func_sym));

  CORE_ADDR regs_addr = module->regs_addr;

  /* Build trampoline */
  unsigned char trampoline_instr[0x80];
  int trampoline_size
      = fill_trampoline (trampoline_instr, func_addr, regs_addr);

  /* Allocate memory for the trampoline in the inferior.  */
  CORE_ADDR trampoline
  //     = allocate_trampoline (gdbarch, sizeof (trampoline_instr));
         = custom_trampoline(gdbarch, insn_addr, sizeof(trampoline_instr));
  /* Copy content of trampoline_instr to inferior memory.  */
  target_write_memory (trampoline, trampoline_instr, trampoline_size);

  /* Relocate replaced instruction */
  CORE_ADDR relocation_address = trampoline + trampoline_size;
  CORE_ADDR trampoline_end = relocation_address;
  CORE_ADDR current_insn_addr = insn_addr;
  while(current_insn_addr < insn_addr +5){
    gdbarch_relocate_instruction (gdbarch, &trampoline_end, insn_addr);
    current_insn_addr += gdb_insn_length(gdbarch, current_insn_addr);
  }
  

  /* Leave enough room for any instruction should another one
     be relocated here */
  trampoline_size += 30;
  /* Fill the void with nops */
  if (gdb_insn_length (gdbarch, insn_addr) > 5)
    {
      const unsigned char NOP_buffer[]
          = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
              0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
      target_write_memory (
          relocation_address + gdb_insn_length (gdbarch, insn_addr),
          NOP_buffer, 15 - gdb_insn_length (gdbarch, insn_addr));
    }

  patch->relocated_insn_address = relocation_address;

  /* Jump back to return address.  */
  int64_t long_jump_offset = return_address - (trampoline_end + 5);
  if (long_jump_offset > INT_MAX || long_jump_offset < INT_MIN)
    {
      /* Trampoline is not freed until program exits */
      fprintf_filtered (
          gdb_stderr,
          "E.Jump pad too far from instruction for jump back (offset 0x%" PRIx64
          " > int32). \n",
          long_jump_offset);
      return 0;
    }

  int32_t jmp_offset = (int32_t)long_jump_offset;
  unsigned char jmp_back[5] = { 0xe9, 0, 0, 0, 0 };
  memcpy (jmp_back + 1, &jmp_offset, 4);
  target_write_memory (trampoline_end, jmp_back, 5);

  return trampoline;
}

int
patch_jump (CORE_ADDR addr, CORE_ADDR trampoline_address,
            struct gdbarch *gdbarch)
{
  int64_t long_jump_offset = trampoline_address - (addr + 5);
  if (long_jump_offset > INT_MAX || long_jump_offset < INT_MIN)
    {
      fprintf_filtered (
          gdb_stderr,
          "E.Jump pad too far from instruction for jump (offset 0x%" PRIx64
          " > int32). \n",
          long_jump_offset);
      return -1;
    }

  int32_t jump_offset = (int32_t)long_jump_offset;
  fprintf_filtered (gdb_stdlog, "jump offset %x from %lx to %lx \n",
                    jump_offset, addr, trampoline_address);
  unsigned char jump_insn[] = { 0xe9, 0, 0, 0, 0 };
  memcpy (jump_insn + 1, &jump_offset, 4);

  /* Add nops to clarify the code if the instruction was too long. 
     These should never be hit.  */
  if (gdb_insn_length (gdbarch, addr) > 5)
    {
      const unsigned char NOP_buffer[] = { 0x90, 0x90, 0x90, 0x90, 0x90,
                                           0x90, 0x90, 0x90, 0x90, 0x90 };
      target_write_memory (addr + 5, NOP_buffer,
                           gdb_insn_length (gdbarch, addr) - 5);
    }

  target_write_memory (addr, jump_insn, 5);
  return 0;
}

/* Convert a string describing a location to an instruction address. */
static CORE_ADDR
location_to_pc (const char *location)
{
  event_location_up event_location
      = string_to_event_location (&location, current_language);
  struct linespec_result canonical;
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

  /* Convert location to an instruction address.  */
  CORE_ADDR addr = location_to_pc (location);

  /* Compile code.  */
  enum compile_i_scope_types scope = COMPILE_I_SIMPLE_SCOPE;
  compile_file_names fnames = compile_to_object (NULL, code, scope, addr);
  // gdb::unlinker object_remover (fnames.object_file ());
  // gdb::unlinker source_remover (fnames.source_file ());
  /* Load compiled code into memory.  */
  struct compile_module *compile_module
      = compile_object_load (fnames, scope, NULL);

  /* Build a trampoline which calls the compiled code.  */
  // CORE_ADDR return_address = find_return_address (gdbarch, &addr, true);
  CORE_ADDR tp_address;
  CORE_ADDR return_address = find_return_address_amad3(gdbarch, &addr, &tp_address, false);
  if (addr != 0)
    {
      Patch *patch = new Patch (compile_module->munmap_list_head, addr);

      CORE_ADDR trampoline_address = build_compile_trampoline (
          gdbarch, compile_module, patch, return_address);

      patch->trampoline_address = trampoline_address;

      /* Patch in the code the jump to the trampoline.  */
      if (trampoline_address != 0
          && patch_jump (addr, trampoline_address, gdbarch) == 0)
        {
          all_patches.add (patch);
        }
      else
        {
          delete patch;
        }
    }
  /* Free unused memory */
  /* Some memory is left allocated in the inferior because
     we still need to access it to execute the compiled code.  */
  // unlink (compile_module->source_file);
  // xfree (compile_module->source_file);
  // // unlink (objfile_name (compile_module->objfile));
  // xfree (compile_module);
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

/* The patch command without a suffix is interpreted as patch code. */
void
compile_patch_command (const char *arg, int from_tty)
{
  compile_patch_code_command (arg, from_tty);
}

/* Handle the input from the 'patch where' command.  The
   "patch where" command is used to print the address of the next
   possible insertion from the address given as argument.  */
void
compile_patch_where_command (const char *arg, int from_tty)
{
  struct gdbarch *gdbarch = target_gdbarch ();

  CORE_ADDR addr = location_to_pc (arg);
  CORE_ADDR new_address = addr;
  find_return_address (gdbarch, &new_address, false);
  if (new_address == 0)
    {
      return;
    }
  struct symtab_and_line sal
      = find_pc_sect_line (new_address, find_pc_section (new_address), 0);

  if (new_address == addr)
    {
      fprintf_filtered (
          gdb_stdlog, "Insertion possible at address 0x%lx on line %d\n",
          new_address, sal.line);
    }
  else
    {
      fprintf_filtered (
          gdb_stdlog, "Insertion not possible at address 0x%lx\n", addr);
      fprintf_filtered (gdb_stdlog,
                        "Next possible address 0x%lx on line %d\n",
                        new_address, sal.line);
    }
}

/* Insert a jump from [from] to [to].  */ 
void
patch_goto(const char *from, const char *to, bool force)
{
  CORE_ADDR addr_from = location_to_pc (from);
  CORE_ADDR addr_to = location_to_pc (to);
  unsigned char jmp_buf[5] = {0xe9, 0x0, 0x0, 0x0, 0x0};
  if(force == 0)
  {
    /* find where to insert the jump */
    struct gdbarch *gdbarch = target_gdbarch();
    find_return_address(gdbarch,&addr_from,false);
  }
  int64_t long_jump_offset = addr_to - addr_from -sizeof(jmp_buf);
  if (long_jump_offset > INT_MAX || long_jump_offset < INT_MIN)
    {
      fprintf_filtered (
          gdb_stderr,
          "E.Destination too far from instruction for jump (offset 0x%" PRIx64
          " > int32). \n",
          long_jump_offset);
      return;
    }

  int32_t jump_offset = (int32_t)long_jump_offset;
  memcpy(jmp_buf+1,&jump_offset,sizeof(jump_offset));
  target_write_memory(addr_from,jmp_buf,sizeof(jmp_buf));

}

/* Check *ARG for a "-forced" or "-f" argument.  Return 0 if not seen.
   Return 1 if seen and update *ARG.  */

static int
check_force_argument (const char **arg)
{
  *arg = skip_spaces (*arg);

  if (arg != NULL
      && (check_for_argument (arg, "-force", sizeof ("-force") - 1)
	  || check_for_argument (arg, "-f", sizeof ("-f") - 1)))
      return 1;
  return 0;
}

/* Handle the input from the 'patch goto' command.  The
   "patch goto" command is used to replace an instruction with a jump
   to a specified location.  */

void
compile_patch_goto_command(const char *arg, int from_tty)
{
  if (arg == NULL)
    {
      error ("No arguments were entered for the patch goto command.");
    }
  int forced = check_force_argument(&arg);
  char *dup = strdup (arg);
  const char *from = strtok (dup, " ");
  const char *to = strtok (NULL, "\0");
  
  if (from == NULL)
    {
      free(dup);
      error ("Missing first argument (\"from\") for the patch goto command.");
    }
  if (to == NULL)
    {
      free(dup);
      error ("Missing second argument (\"to\") for the patch goto command.");
    }
  patch_goto(from,to,forced);
  
  free (dup);
}

/* Handle the input from the 'patch list' command.  The
   "patch list" command is used to display all active patches in 
   the inferior.  */
void
compile_patch_list_command (const char *arg, int from_tty)
{
  auto it = all_patches.patches.begin ();
  int i = 1;
  for (; it != all_patches.patches.end (); it++)
    {
      if (it->active)
        {
          fprintf_filtered (gdb_stdlog, "%i  address: 0x%lx\n", i,
                            (it->patch)->address);
          
        }
      i++;
    }
}

/* Handle the input from the 'patch delete' command.  The
   "patch delete" command is used to remove a patch from the inferior.
   It expects an index as argument.  */
void
compile_patch_delete_command (const char *arg, int from_tty)
{
  struct gdbarch *gdbarch = target_gdbarch ();

  if (arg == NULL)
    {
      fprintf_filtered (gdb_stdlog,
                        "patch delete needs a patch index. \n");
      return;
    }
  int index = atoi (arg)-1;
  if (index == -1)
  {
    auto it = all_patches.patches.begin ();
    int i = 1;
    char index_string[10];
    for (; it != all_patches.patches.end (); it++)
      {
        if (it->active)
          {
            printf("deleting patch %d\n",i);
            sprintf(index_string,"%d",i);
            compile_patch_delete_command(index_string,0);
          }
        i++;
      }
    return;
  }

  Patch *patch = all_patches.find_index (index);
  if (patch == NULL)
    {
      fprintf_filtered (gdb_stdlog,
                        "No patch has been found for index %d\n", index+1);
      return;
    }
  std::vector<Patch *> patches_at_address
      = all_patches.find_address (patch->address);

  CORE_ADDR to_change = patch->address;

  auto it = patches_at_address.begin ();
  for (; *it != patch; it++)
    {
    };
  it++;
  if (it != patches_at_address.end ())
    {
      to_change = (*it)->relocated_insn_address;
    }

  gdbarch_relocate_instruction (gdbarch, &to_change,
                                patch->relocated_insn_address);

  all_patches.remove (index);
  delete patch;
}

void
compile_patch_store_command (const char *arg, int from_tty)
{
  all_patches.store(arg);
}

void
compile_patch_load_command (const char *arg, int from_tty)
{
  all_patches.load(arg);
}

/* Called on inferior exit. We reset everything */
void
reset_patch_data (struct inferior *inferior)
{
  /* Reset the mmap values for trampolines */
  allocate_trampoline (NULL, -1, 0, 0);

  /* Delete all live patches object */
  auto it = all_patches.patches.begin ();
  for (; it != all_patches.patches.end (); it++)
    {
      if (it->active)
        {
          delete it->patch;
        }
    }
  /* Reset the list of patches */
  all_patches = PatchVector ();
}
