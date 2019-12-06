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
#include "patch.h"
#include "cli/cli-utils.h"
#include <unordered_map>
#include <map>

#define FIXED_POS 0
#define ANYWHERE 1
#define JUST_ASKING 2
PatchVector all_patches;
Patch *current_patch;

static int 
mov_reg(unsigned char *trampoline_instr, struct regs_store_data reg_store_info)
{
  int correct[16]={0,3,1,2,6,7,5,4,8,9,10,11,12,13,14,15};
  ULONGEST offset = reg_store_info.reg_offset;
  int regnum = reg_store_info.regnum;
  if(regnum == -1)
  {
    // Dummy register
    return 0;
  }
  if(regnum>15 || regnum < 0)
  {
    fprintf_filtered(gdb_stdlog, "Expected register number < 16\n");
    fprintf_filtered(gdb_stdlog, "Got number %d \n", regnum);
    return 0;
  }
  regnum = correct[regnum];

  int i = 0;
  if(regnum<8)
    trampoline_instr[i++] = '\x48';
  else
    trampoline_instr[i++] = '\x4c';
  trampoline_instr[i++] = '\x89';
  trampoline_instr[i++] = '\x87'+'\x8'*(regnum%8);
  int32_t offset32 = (int32_t) offset;
  memcpy(trampoline_instr+i, &offset32, 4);
  i+=4;
  return i;
}
/* Fills the trampoline but does not relocate the replaced instruction */
int
fill_trampoline (unsigned char *trampoline_instr, CORE_ADDR called,
                 CORE_ADDR arg_regs, struct regs_store_data *regs_store_info, int regs_store_len)
{

  int i = 0;
  /* save registers */
  /* flags may cause bug when stepped over */
  trampoline_instr[i++] = 0x9c; /* pushfq */ 

  /* rsp -= 0x80 for the red zone */
  trampoline_instr[i++] = 0x48; 
  trampoline_instr[i++] = 0x83; 
  trampoline_instr[i++] = 0xc4; 
  trampoline_instr[i++] = 0x80; 
  /* or */
  /* Store rax at rsp -0x80 */
  /* Move flags to ah */
  /* add -0x88 to rsp */
  /* push regs  */
  /* pop every reg */
  /* add 0x88 to rsp */
  /* mov ah to flags */
  
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

  trampoline_instr[i++] = 0x55; /* push %rbp for stack alignement */

      

  /* provide gdb_expr () arguments */
  trampoline_instr[i++] = 0x48; /* movabs <arg>,%rdi */
  trampoline_instr[i++] = 0xbf;
  memcpy (trampoline_instr + i, &arg_regs, 8);
  i += 8;
  for(int j =0; j < regs_store_len; j++)
  {
    i += mov_reg(trampoline_instr+i, regs_store_info[j]);
  }
  // trampoline_instr[i++] = 0x48; /* mov %rbp, (%rdi) */
  // trampoline_instr[i++] = 0x89;
  // trampoline_instr[i++] = 0x2f;

  /* call gdb_expr () */
  trampoline_instr[i++] = 0x48; /* movabs <called>,%rax */
  trampoline_instr[i++] = 0xb8;
  memcpy (trampoline_instr + i, &called, 8);
  i += 8;
  trampoline_instr[i++] = 0xff; /* callq *%rax */
  trampoline_instr[i++] = 0xd0;

  /* restore registers */
  trampoline_instr[i++] = 0x5d; /* pop %rbp (stack alignment)*/

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
  trampoline_instr[i++] = 0x58; /* pop %rbx */
  trampoline_instr[i++] = 0x5b; /* pop %rbx */
  trampoline_instr[i++] = 0x59; /* pop %rcx */
  trampoline_instr[i++] = 0x5a; /* pop %rdx */
  trampoline_instr[i++] = 0x5e; /* pop %rsi */
  trampoline_instr[i++] = 0x5f; /* pop %rdi */
  trampoline_instr[i++] = 0x5d; /* pop %rbp */
  trampoline_instr[i++] = 0x5c; /* pop %rsp */
  /* rsp += 0x80 */
  trampoline_instr[i++] = 0x48; 
  trampoline_instr[i++] = 0x81; 
  trampoline_instr[i++] = 0xc4; 
  trampoline_instr[i++] = 0x80; 
  trampoline_instr[i++] = 0x00; 
  trampoline_instr[i++] = 0x00; 
  trampoline_instr[i++] = 0x00; 
  trampoline_instr[i++] = 0x9d; /* popfq */

  return i;
}

int
build_datawatch_tp(unsigned char* buf, CORE_ADDR memory_check_function, int mem_access_registers)
{
  /* table for fast log2 calculation */
  const gdb_byte log_table[]={0b0,0b0,0b1,0b0,0b10,0b0,0b0,0b11};
  /* For now, only x64 architecture */
  int i = 0;
  int stack_offset = 0;

  /* save registers */
  /* flags may cause a bug when stepped over */
  buf[i++] = 0x9c; /* pushfq */ 


  /* rsp -= 0x80 for the red zone */
  buf[i++] = 0x48; 
  buf[i++] = 0x83; 
  buf[i++] = 0xc4; 
  buf[i++] = 0x80; 

  buf[i++] = 0x54; /* push %rsp */
  buf[i++] = 0x55; /* push %rbp */
  buf[i++] = 0x57; /* push %rdi */
  buf[i++] = 0x56; /* push %rsi */
  buf[i++] = 0x53; /* push %rbx */
  buf[i++] = 0x52; /* push %rdx */
  buf[i++] = 0x51; /* push %rcx */
  buf[i++] = 0x50; /* push %rax */
  buf[i++] = 0x41;
  buf[i++] = 0x54; /* push %r12 */
  buf[i++] = 0x41;
  buf[i++] = 0x55; /* push %r13 */
  buf[i++] = 0x41;
  buf[i++] = 0x57; /* push %r15 */
  buf[i++] = 0x41;
  buf[i++] = 0x56; /* push %r14 */
  buf[i++] = 0x41;
  buf[i++] = 0x53; /* push %r11 */
  buf[i++] = 0x41;
  buf[i++] = 0x52; /* push %r10 */
  buf[i++] = 0x41;
  buf[i++] = 0x51; /* push %r9 */
  buf[i++] = 0x41;
  buf[i++] = 0x50; /* push %r8 */

  

  /* In mem_access_registers we store :
    base : 4 bits
    index : 4 bits
    scale : 2 bits
    disp : 12 bits
    whether the access is simple or has a (index,scale) attribute : 1 bit
    multiple mem operands : 1 bit 
    whether to restore each register 1 bit each*/

  gdb_byte reg = mem_access_registers & 0xF;
  gdb_byte idx = (mem_access_registers & 0xF0)>>4;
  gdb_byte scale = (mem_access_registers & 0xF00)>>8; 
  gdb_byte scale_log = log_table[scale];
  int16_t disp = (mem_access_registers & 0xFFF000)>>(4*3);
  gdb_byte mem_with_idx = (mem_access_registers & 0x10000000)>>(4*7);
  gdb_byte multiple_mem_operands = (mem_access_registers & 0x40000000)>>30;
  if(mem_with_idx>0)
  {
    multiple_mem_operands = 1;
  }

  if(multiple_mem_operands == 1)
  /* An instruction with two differents registers accessed i.e. movs or compsd */
  {
    /* Do the same thing with the second register
       disp is necessarily 0 */
    
    /* mov <idx> rdi */
    buf[i++] = 0x48; 
    buf[i++] = 0x8b; 
    buf[i++] = 0x7c; 
    buf[i++] = 0x24; 
    buf[i++] = (gdb_byte) 0x8*(15-idx + stack_offset); 
    /* mov rdi rsi (disp = 0)*/
    buf[i++] = 0x48; 
    buf[i++] = 0x89; 
    buf[i++] = 0xfe; 
    /* absolute call memory_check() */
    buf[i++] = 0x48; /* movabs <memcheck_function>,%rax */
    buf[i++] = 0xb8;
    memcpy (buf + i, &memory_check_function, 8);
    i += 8;
    buf[i++] = 0xff; /* callq *%rax */
    buf[i++] = 0xd0;
    /* push result on the stack */
    buf[i++] = 0x50; /* push %rax */

    stack_offset ++;
  }

    /* mov <reg_value>, %rdi */
  buf[i++] = 0x48; 
  buf[i++] = 0x8b; 
  buf[i++] = 0x7c; 
  buf[i++] = 0x24; 
  buf[i++] = (gdb_byte) 0x8*(15-reg + stack_offset); /* used to have +1 for fq */
  if(mem_with_idx == 0)
  /* A simple memory access : rsi = rdi + disp */
  {
    buf[i++] = 0x48; /* lea disp(%rdi), %rsi */
    buf[i++] = 0x8d;
    if((disp > 0x80) || (disp < -0x80))
    {
      buf[i++]=0xb7;
      memcpy (buf + i, &disp, 2);
      i+=2;
      buf[i++]=0;
      buf[i++]=0;
    }
    else
    {
      buf[i++] = 0x77; 
      buf[i++] = (gdb_byte) disp; 
    }
  }
  else
  {
    /* load the initial index register to rax, so that there is no interference 
    if it was rdi or rsi. */
    // buf[i++] = 0x48; 
    // buf[i++] = 0x8b; 
    // buf[i++] = 0x44; 
    // buf[i++] = 0x24; 
    // buf[i++] = (gdb_byte) 0x08*(15-idx + stack_offset); /* used to be +1 for the flags */

    /* We copy the actual address to rsi and the base address to rdi.
      the memory checker funciton will check that rsi is valid and correct rdi.
      This is done because we cannot simply revert a lea instruction. */
    /* lea disp(rdi,rax,scale_log), %rsi*/
    buf[i++] = 0x48; /* 64 bit lea  */
    buf[i++] = 0x8d; 
    buf[i++] = 0x74; /* ModR/M : to rsi + SIB w 8bit displacement */
    buf[i++] = (scale_log<<6) + 0x0 + 0x7; /* SIB : [scale 2| index(rax) 3| base(rdi) 3] */
    buf[i++] = disp; 
  }

  /* absolute call memory_check() */
  buf[i++] = 0x48; /* movabs <memcheck_function>,%rax */
  buf[i++] = 0xb8;
  memcpy (buf + i, &memory_check_function, 8);
  i += 8;
  buf[i++] = 0xff; /* callq *%rax */
  buf[i++] = 0xd0;
  /* push result on the stack */
  buf[i++] = 0x50; /* push %rax */
  stack_offset ++;

  
  
  /* I do not store all registers in a logical order 
     so that rsp and rbp are handled first / last */
  gdb_byte pop_insns[] =
    {0x5c,0x5d,0x5f,0x5e,0x5b,0x5a,0x59,0x58};
  /* restore the modified register(s) */
  if(reg >= 8)
    buf[i++] = 0x41;
  buf[i++] = pop_insns[reg%8];
  if(multiple_mem_operands == 1)
  {
    if(idx >= 8)
      buf[i++] = 0x41;
    buf[i++] = pop_insns[idx%8];
  }
  /* restore the other registers */
  for(int pop_index = 15; pop_index>=0; pop_index--)
  {
    if(reg != pop_index && (multiple_mem_operands == 0 || idx!=pop_index))
    {
      if(pop_index>=8)
      {
        buf[i++] = 0x41;
      }
      buf[i++] = pop_insns[pop_index%8];
    }
    else
    {
      /* Increment stack pointer */
      buf[i++] = 0x48;
      buf[i++] = 0x83;
      buf[i++] = 0xc4;
      buf[i++] = 0x08; 
    }
  }
  /* rsp += 0x80 */
  buf[i++] = 0x48; 
  buf[i++] = 0x81;
  buf[i++] = 0xc4; 
  buf[i++] = 0x80; 
  buf[i++] = 0x00; 
  buf[i++] = 0x00; 
  buf[i++] = 0x00; 

  buf[i++] = 0x9d; /* popfq */


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

  CORE_ADDR return_address
          = *insn_addr + gdb_insn_length (gdbarch, *insn_addr);
  while (return_address < *insn_addr + 5)
  {
    return_address+=gdb_insn_length (gdbarch, return_address);
  }
  return return_address;
  
}


/* Is this page available ? If so map it */
CORE_ADDR
can_mmap(gdbarch *gdbarch, CORE_ADDR addr, int trampoline_size)
{
  const int prot = 7;
  const int page_size = 0x1000;
  CORE_ADDR mmapped_area = gdbarch_infcall_mmap(gdbarch, addr, trampoline_size, prot);
  // printf("addr 0x%lx mmapped_area 0x%lx size %d \n", addr, mmapped_area,trampoline_size);
  if(mmapped_area + page_size > addr && mmapped_area <= addr)
  {
    if(mmapped_area + page_size < addr+trampoline_size)
    {
      CORE_ADDR second_mmap = gdbarch_infcall_mmap(gdbarch, mmapped_area + page_size, trampoline_size, prot);
      if(second_mmap == mmapped_area + page_size)
      {
        return mmapped_area;
      }
      else
      {
        gdbarch_infcall_munmap(gdbarch,mmapped_area,page_size);
        gdbarch_infcall_munmap(gdbarch,second_mmap,page_size);
        return (CORE_ADDR) 0;
      }
    }
    return mmapped_area;
  }
  gdbarch_infcall_munmap(gdbarch,mmapped_area,page_size);
  return (CORE_ADDR) 0;
}

CORE_ADDR try_put_trampoline(gdbarch *gdbarch, CORE_ADDR tp_address, int pos_policy)
{
  static std::unordered_map<CORE_ADDR, std::map<CORE_ADDR, CORE_ADDR> *> page_map;
  const unsigned long tp_size = 0x100;
  const unsigned int page_size = 0x1000;
  CORE_ADDR page_address = (tp_address >> 12) << 12; /* Assuming a page size of 0x1000 !*/
  
  if(pos_policy == FIXED_POS)
  {
    CORE_ADDR lower_bound = page_address;
    CORE_ADDR upper_bound = page_address + page_size;
    if (page_map.find(page_address) != page_map.end())
    {
      std::map<CORE_ADDR, CORE_ADDR> *tp_map = page_map[page_address];
      auto it = tp_map->upper_bound(tp_address); /* first element after tp_address */
      
      if(it == tp_map->end())
      {
        auto rit = tp_map->rbegin();
        lower_bound = rit->second;
      }
      else
      {
        upper_bound = it->first;
        lower_bound = (--it)->second;
        if(lower_bound > upper_bound)
        {
          lower_bound = page_address;
        }
      }
      if(lower_bound<=tp_address && upper_bound>tp_address+ tp_size)
      {
        // fprintf_filtered(gdb_stdlog,"3 inserted tp at address 0x%lx\n", tp_address);
        // fprintf_filtered(gdb_stdlog,"lower 0x%lx upper 0x%lx\n", lower_bound, upper_bound);
        tp_map->insert({tp_address, tp_address+tp_size});
        return tp_address;
      }
      /* Memory is already taken by another jump pad */
      return 0;
    }
    if(can_mmap(gdbarch, tp_address,tp_size))
    {
      page_map.insert({page_address, new std::map<CORE_ADDR, CORE_ADDR>()});
      // fprintf_filtered(gdb_stdlog,"4 inserted tp at address 0x%lx\n", tp_address);
      page_map[page_address]->insert({tp_address, tp_address + tp_size});
      return tp_address;
    }
    else
    {
      /* Maybe the trampoline is at the end of an unmapped page but the next
         page is already mapped but available. Check that */
      if(tp_address+tp_size>page_address+page_size &&
         page_map.find(page_address+page_size) != page_map.end())
      {
        std::map<CORE_ADDR, CORE_ADDR> *tp_map = page_map[page_address+page_size];
        auto it = tp_map->begin();
        upper_bound = it->first;
        if(tp_address + tp_size < upper_bound &&
           can_mmap(gdbarch, tp_address,1))
        {
          page_map.insert({page_address, new std::map<CORE_ADDR, CORE_ADDR>()});
          // fprintf_filtered(gdb_stdlog,"5 inserted tp at address 0x%lx\n", tp_address);
          page_map[page_address]->insert({tp_address, page_address + page_size});
          return tp_address;
        }
      }
    }
    return (CORE_ADDR) 0;
  }
  else
  {
    int increments = 0;
    int MAX_INCREMENTS=20;
    while(1)
    {
      if (page_map.find(page_address) != page_map.end())
      {
        auto tp_map = page_map[page_address];
        auto rit = tp_map->rbegin();
        CORE_ADDR lower_bound = rit->second;
        if(lower_bound + tp_size > page_address + page_size)
        {
          page_address+=page_size;
          continue;
        }
        if (pos_policy != JUST_ASKING)
        {
          // fprintf_filtered(gdb_stdlog,"1 inserted tp at address 0x%lx\n", lower_bound);
          page_map[page_address]->insert({lower_bound, lower_bound + tp_size});
        }
        return lower_bound;
      }
      if(can_mmap(gdbarch, page_address,tp_size))
      {
        page_map.insert({page_address, new std::map<CORE_ADDR, CORE_ADDR>()});
        if (pos_policy != JUST_ASKING)
        {
          // fprintf_filtered(gdb_stdlog,"2 inserted tp at address 0x%lx\n", page_address);
          page_map[page_address]->insert({page_address, page_address + tp_size});
        }
        else
        {
          // fprintf_filtered(gdb_stdlog,"Did not insert tp at address 0x%lx\n", page_address);
          page_map[page_address]->insert({page_address-1, page_address});
        }
        return page_address;
      }
      else
      {
        increments++;
        page_address+=page_size;
        fprintf_filtered(gdb_stdlog, "mmap failed for address 0x%lx tp 0x%lx\n", page_address, tp_address);
        if(increments > MAX_INCREMENTS)
        {
          error(_("ERROR : Unable to mmap a new region."));
        }
      }
    }
  }
}

/* Allocate some space for a trampoline for a regular 5 byte jump. */
CORE_ADDR
allocate_trampoline (struct gdbarch *gdbarch, int size, CORE_ADDR addr)
{
  CORE_ADDR minimum_address;
    if(addr > (1<<29))
      minimum_address = ((addr>>29) - 0x1)<<29;
    else
      minimum_address = 0x100000;
  CORE_ADDR tp_address = try_put_trampoline(gdbarch, minimum_address, ANYWHERE);
  
  if(tp_address == 0)
  {
    error(_("ERROR : Failed to allocate a trampoline."));
  }
  return tp_address;
}

/* Choose where to put the trampoline */
CORE_ADDR
place_trampoline(gdbarch *gdbarch, CORE_ADDR *addr, int lengths[])
{
  const gdb_byte ill_insns[14] = {6, 7, 14, 22, 23, 30, 31, 39, 47, 55, 63, 96, 97, 98};

  if(lengths[4] > 0) // insn beginning on 5th byte
  {
    int32_t offset = 0;
    target_read_memory(*addr+1,((gdb_byte *)&offset),3);
    for( int idx = 0; idx< 14; idx++)
    {
      memcpy(((gdb_byte *)&offset)+3,&ill_insns[idx],1);
      CORE_ADDR tp_address = *addr+offset+5;
      // Not unmappable, TODO : make it cleanable
      if(tp_address >= 0x800000000000)
      {
        continue;
      }
      if (try_put_trampoline(gdbarch,tp_address, FIXED_POS)!=0)
      {
        return tp_address;
      }
    }
    if(lengths[4]>1)
    {
      for(int i = 0; i< 4; i++)
        lengths[i]=lengths[i+1];
      lengths[4]=0;
      *addr= *addr + 1;
      return place_trampoline(gdbarch, addr, lengths);
    }
    error(_("No suitable destination for tp"));
  }
  else
  {
    CORE_ADDR minimum_address;
    if(*addr > (1<<29))
      minimum_address = ((*addr>>29) - 0x1)<<29;
    else
      minimum_address = 0x100000;
    CORE_ADDR tp_address = try_put_trampoline(gdbarch, minimum_address, JUST_ASKING);
    if(tp_address == 0)
    {
      printf("This should not happen \n");
    }
    int32_t preoffset = tp_address - (*addr + 5) ;
    int32_t offset = preoffset;
    /* Default illegal instruction */
    gdb_byte ill_insn = 0x6;
    int mini = 0;
    for (int i = 1; i< 5; i++)
    {
      if(lengths[i]>0)
      {
        memcpy( ((gdb_byte *) &offset) + i-1, &ill_insn, 1);
        if(mini == 0)
          mini=i;
      }
      else if(mini!=0)
        target_read_memory(*addr+i, ((gdb_byte *) &offset) + i-1, 1);
    }
    tp_address = *addr + offset + 5;
    for(int i = 0; i<255; i++)
    {
      /* We increment the most significant byte */
      offset+=1<<(8*3); 
      tp_address = *addr + offset + 5;
      if(tp_address >= 0x800000000000)
      {
        continue;
      }
      if(try_put_trampoline(gdbarch, tp_address, FIXED_POS)!=0)
      {
        return tp_address;
      }
    }
    error(_("Failed to allocate a trampoline."));
  }
  return (CORE_ADDR) 0;
}


/* Analyze the layout */
CORE_ADDR
analyse_layout(gdbarch *gdbarch, CORE_ADDR *addr)
{
  CORE_ADDR current_address = *addr;
  int insn_length;
  gdb_byte instructions[30];
  int lengths[5]={0,0,0,0,0};
  while (current_address < *addr +5)
  {
    insn_length = gdb_insn_length(gdbarch, current_address);
    lengths[(int)(current_address - *addr)] = insn_length;
    current_address += insn_length;
  }
  target_read_memory(*addr, instructions, (int) (current_address - *addr));

  return place_trampoline(gdbarch, addr, lengths);
}


CORE_ADDR custom_trampoline(struct gdbarch *gdbarch, CORE_ADDR *insn_address, int size)
{
  if(gdb_insn_length(gdbarch,*insn_address)>=5)
  {
    return allocate_trampoline(gdbarch,size, *insn_address);
  }
  
  return analyse_layout(gdbarch, insn_address);
}

CORE_ADDR
build_compile_trampoline (struct gdbarch *gdbarch,
                          struct compile_module *module, Patch *patch,
                          CORE_ADDR return_address, int mem_access_regs)
{
  CORE_ADDR insn_addr = patch->address;

  /* Build trampoline */
  unsigned char trampoline_instr[0x100];
  int trampoline_size;
  if(mem_access_regs == 0)
  {
    struct symbol *func_sym = module->func_sym;
    CORE_ADDR func_addr = BLOCK_ENTRY_PC (SYMBOL_BLOCK_VALUE (func_sym));
    CORE_ADDR regs_addr = module->regs_addr;
    struct regs_store_data *regs_store_info = module->regs_store_info;
    int reg_store_len = module->regs_store_len;
    trampoline_size = fill_trampoline (trampoline_instr, func_addr, regs_addr, regs_store_info, reg_store_len);
  }
  else
  {
    CORE_ADDR mem_access_fun = module->out_value_addr;
    trampoline_size = build_datawatch_tp(trampoline_instr, mem_access_fun, mem_access_regs);
  }
  CORE_ADDR current_insn_addr = insn_addr;

  /* Allocate memory for the trampoline in the inferior.  */
  CORE_ADDR trampoline
         = custom_trampoline(gdbarch, &insn_addr, sizeof(trampoline_instr));
  /* Copy content of trampoline_instr to inferior memory.  */
  target_write_memory (trampoline, trampoline_instr, trampoline_size);

  /* Relocate replaced instruction */
  CORE_ADDR relocation_address = trampoline + trampoline_size;
  CORE_ADDR trampoline_end = relocation_address;

  /* Relocate the first instruction */
  gdb_byte buf[5];
  target_read_memory(current_insn_addr, buf, 5);
  gdbarch_relocate_instruction (gdbarch, &trampoline_end, current_insn_addr);
  int insn_length = gdb_insn_length(gdbarch, current_insn_addr);
  if (current_insn_addr != insn_addr)
  {
    patch->offset_address();
    
    const gdb_byte nop = '\x90';
    target_write_memory(current_insn_addr, &nop, 1);
  }
  current_insn_addr = current_insn_addr + insn_length;


  /* Restore the register to its previous value */
  const gdb_byte dest_reg[] =
    {0x64,0x6c,0x7c,0x74,0x5c,0x54,0x4c,0x44};
  /* rsp  rbp  rdi  rsi  rbx  rdx  rcx  rax*/
  /* r12  r13  r15  r14  r11  r10  r9   r8 */
  if((mem_access_regs>>29) & 1) /* register access is read only */
  {
    int reg = mem_access_regs&0xF;
    int offset = -8*(2+reg) -0x80; /* 1 for the flags + 1 because rsp points after the end of the stack ,0x80 because of the red zone */
    gdb_byte insn[8] = {0x48,0x8b,0x0,0x24,0x0,0x0,0x0,0x0};
    /* We need a 32 bit disp. Only necessary if offset <= -128 (reg>=14) */
    if(reg>=8) 
    {
      insn[0]=0x4c;
    }
    insn[2]=dest_reg[reg%8]+0x40;
    memcpy(insn+4, &offset, 4);
    target_write_memory(trampoline_end, insn,8);
    trampoline_end += 8;
    // }
    // else
    // {
    //   insn[2]=dest_reg[reg%8];
    //   insn[4]=(gdb_byte) offset;
    //   target_write_memory(trampoline_end, insn,5);
    //   trampoline_end += 5;
    // }
    if((mem_access_regs & 0x8000000)>>(30) == 1)
    {
      /* restore the idx register too */
      reg = (mem_access_regs&0xF0)>>4;
      insn[0]=0x48;
      offset = -8*(2+reg); /* 1 for the flags + 1 because rsp points after the end of the stack */
      if(reg>=8) /* We need a 32 bit disp. Only valid if offset <= -128 (reg>=14) */
      {
        insn[0]=0x4c;
        insn[2]=dest_reg[reg%8]+0x40;
        memcpy(insn+4, &offset, 4);
        target_write_memory(trampoline_end, insn,8);
        trampoline_end += 8;
      }
      else
      {
        insn[2]=dest_reg[reg%8];
        insn[4]=(gdb_byte) offset;
        target_write_memory(trampoline_end, insn,5);
        trampoline_end += 5;
      }
    }
    
  }
  /* Relocate the other instructions */
  while(current_insn_addr < insn_addr +5)
  {
    if(gdbarch_relocate_instruction (gdbarch, &trampoline_end, current_insn_addr) < 0)
    {
      /* The instruction cannot be relocated (jump offset may be too large).
        We jump back to the original instruction address, at the expense of 
        a sigill every time. */
      break;
    }
    current_insn_addr += gdb_insn_length(gdbarch, current_insn_addr);
  }

  patch->relocated_insn_address = relocation_address;

  /* Jump back to return address.  */
  int64_t long_jump_offset = current_insn_addr - (trampoline_end + 5);
  if (long_jump_offset > INT_MAX || long_jump_offset < INT_MIN)
    {
      /* Trampoline is not freed until program exits */
      fprintf_filtered (
          gdb_stderr,
          "E.Jump pad too far from instruction for jump back (offset 0x%" PRIx64
          " > int32). \n\
          Jump to 0x%lx from 0x%lx \n",
          long_jump_offset, return_address, trampoline_end);
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
  fprintf_filtered (gdb_stdlog, "jump offset 0x%x from 0x%lx to 0x%lx \n",
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

/* The central function for the patch command. 
   If mem_access_regs != 0, location represents the memory_access function*/
static void
patch_code (const char *location, const char *code, int mem_access_regs)
{
  struct gdbarch *gdbarch = target_gdbarch ();
  struct compile_module *compile_module;
  CORE_ADDR addr;
  struct compile_module cm;
  if(mem_access_regs == 0)
  {
    /* Convert location to an instruction address.  */
    addr = location_to_pc (location);

    /* Compile code.  */
    enum compile_i_scope_types scope = COMPILE_I_SIMPLE_SCOPE;
    compile_file_names fnames = compile_to_object (NULL, code, scope, addr);
    
    /* FIXME : memory not freed for debug purposes */
    // gdb::unlinker object_remover (fnames.object_file ());
    // gdb::unlinker source_remover (fnames.source_file ());
    /* Load compiled code into memory.  */
    scope = COMPILE_I_PATCH_SCOPE;
    compile_module = compile_object_load (fnames, scope, NULL);
  }
  else
  {
    addr = get_frame_pc (get_selected_frame (NULL));
    /* We use out_value_addr to store the memory access function address */
    compile_module = &cm;
    compile_module->out_value_addr = location_to_pc (location);
    compile_module->munmap_list_head = 0;
  }

  /* Build a trampoline which calls the compiled code.  */
  CORE_ADDR tp_address;

  CORE_ADDR return_address = find_return_address_amad3(gdbarch, &addr, &tp_address, false);

  if (addr != 0)
    {
      Patch *patch = new Patch (compile_module->munmap_list_head, addr);
      patch->read_original_insn(gdbarch, 0);

      CORE_ADDR trampoline_address = build_compile_trampoline (
          gdbarch, compile_module, patch, return_address, mem_access_regs);
      
      addr = patch->address;
      patch->trampoline_address = trampoline_address;
      
      /* Patch in the code the jump to the trampoline.  */
      if (trampoline_address != 0
          && patch_jump (addr, trampoline_address, gdbarch) == 0)
        {
          if(current_patch != NULL)
          {
            /* We are in a sigill handling situation, 
               we need to update the previous patch's data */
            int offset = addr - current_patch->address;
            if(offset > 0 && offset<5 )
            {
              current_patch->read_original_insn(gdbarch, offset);
            }
          }
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
  /* FIXME : For now, memory is not deallocated to be able to debug the added code */
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
  patch_code (location, code, 0);
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
  patch_code (location, code_buf.c_str (), 0);
  free (dup);
}

/* The patch command without a suffix is interpreted as patch code. */
void
compile_patch_command (const char *arg, int from_tty)
{
  compile_patch_code_command (arg, from_tty);
}

/* Handle the input from the 'patch dw' command.  The
   "patch dw" command is used to patch in the code a 
   memory checker for registers before an instruction */
void
compile_patch_dw_command (const char *arg, int from_tty)
{
  if (arg == NULL)
    {
      error ("No arguments were entered for the patch dw command.");
    }
  char *dup = strdup (arg);
  const char *location = strtok (dup, " ");
  const char *regs_str = strtok (NULL, "\0");
  int read_registers = atoi(regs_str);
  if(read_registers == 0)
    {
      error ("No registers read by the faulty instruction.");
    }
  patch_code (location, NULL, read_registers);
  free (dup);
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
    int16_t i = 1;
    char index_string[10];
    for (; it != all_patches.patches.end (); it++)
      {
        if (it->active)
          {
            fprintf_filtered(gdb_stdlog,"deleting patch %d\n",i);
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
  // allocate_trampoline (NULL, -1, 0, 0);

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

void
patch_sigill_handler(const char *arg, int from_tty)
{
  static CORE_ADDR sig_addr;
  static gdb_byte buffer[4];
  
  if(!strcmp(arg,"1"))
  {
    sig_addr = get_frame_pc (get_selected_frame (NULL));
    
    /* Find which patch causes the problem. We need to pinpoint the patch closest to the issue */
    auto it = all_patches.patches.begin ();
    int max_offset = 6;
    for (; it != all_patches.patches.end (); it++)
      {
        int patch_offset = sig_addr - it->patch->address;
        if (it->active && patch_offset>0 && patch_offset<max_offset)
          {
            max_offset = patch_offset;
            current_patch = it->patch;
          }
      }
      /* Reposition instruction */
      if(max_offset<6)
      {
        target_read_memory(sig_addr,buffer, 4);
        target_write_memory(sig_addr,current_patch->original_insn + max_offset,5-max_offset);
      }
  }
  else
  {
    if(current_patch != NULL || from_tty != 42)
    {
      current_patch = NULL;
      target_write_memory(sig_addr,buffer,4);
    }
  }
} 