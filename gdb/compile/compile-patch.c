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
#include "unistd.h"
#include "patch.h"
#include "location.h"
#include <map>

#define PAGE_SIZE sysconf(_SC_PAGE_SIZE)
#define PAGE_ADDRESS(addr) (addr/PAGE_SIZE)*PAGE_SIZE
#define TP_MAX_SIZE 0x100

static PatchMap registered_patches;

typedef std::map<CORE_ADDR,CORE_ADDR> page_map_t;
static std::map<CORE_ADDR, page_map_t*> compile_memory_map;

#define VALID_ADDRESS(addr) ((addr>0x10000)&&(addr<0x800000000000))
#define ILL_INSN_CNT 14
#define MAX_INT8 127

/* Stores the breakpoint kind (i.e. 10+size) of patch breakpoints
   at their address. */
static std::map<CORE_ADDR,int> ill_insn_patches_kind;

/* Finds the return address for a trampoline placed at insn_addr.  */
static CORE_ADDR
find_return_address (struct gdbarch *gdbarch, CORE_ADDR insn_addr,
                     bool verbose)
{
  /* In this version, we assume that we can always put a jump to a trampoline
      that returns at the next instruction after a jump instruction.  */
  CORE_ADDR return_address
          = insn_addr + gdb_insn_length (gdbarch, insn_addr);
  while (return_address < insn_addr + gdbarch_jmp_insn_length(gdbarch,0))
  {
    return_address+=gdb_insn_length (gdbarch, return_address);
  }
  return return_address;
}

/* Is the page containing addr available ? If so map it.  */
static CORE_ADDR
try_map_page(gdbarch *gdbarch, CORE_ADDR trampoline_addr, int trampoline_size)
{
  int page_size = PAGE_SIZE;
  const int prot = GDB_MMAP_PROT_READ | GDB_MMAP_PROT_WRITE | GDB_MMAP_PROT_EXEC;

  CORE_ADDR mapped_page = gdbarch_infcall_mmap(gdbarch, trampoline_addr, 1, prot);

  if(mapped_page != PAGE_ADDRESS(trampoline_addr))
  {
    compile_memory_map.insert({mapped_page,NULL});
    gdbarch_infcall_munmap(gdbarch, mapped_page, page_size);
    return (CORE_ADDR) 0;
  }

  /* Check if the trampoline overlaps several pages.  */
  if(mapped_page + page_size < trampoline_addr + trampoline_size)
  {
    CORE_ADDR second_page = gdbarch_infcall_mmap(gdbarch, mapped_page + page_size, page_size, prot);
    if(second_page == mapped_page + page_size)
    {
      page_map_t *new_page_map = new std::map<CORE_ADDR,CORE_ADDR>();
      compile_memory_map.insert({mapped_page,new_page_map});
      page_map_t *new_page_map_2 = new std::map<CORE_ADDR,CORE_ADDR>();
      compile_memory_map.insert({second_page,new_page_map_2});
      return mapped_page;
    }
    else
    {
      compile_memory_map.insert({second_page,NULL});
      gdbarch_infcall_munmap(gdbarch, mapped_page, page_size);
      gdbarch_infcall_munmap(gdbarch, second_page, page_size);
      return (CORE_ADDR) 0;
    }
  }
  page_map_t *new_page_map = new std::map<CORE_ADDR,CORE_ADDR>();
  compile_memory_map.insert({mapped_page,new_page_map});
  return mapped_page;
}
CORE_ADDR
base_address(gdbarch *gdbarch, CORE_ADDR address)
{
  int bit_shift = gdbarch_jmp_insn_length(gdbarch, 1)*8 - 3;
  CORE_ADDR base_addr = ((address>>bit_shift) > 0 ? (((address>>bit_shift) -1)<<bit_shift) : 100*PAGE_SIZE);
  return base_addr;
}
CORE_ADDR
start_of_page(gdbarch *gdbarch, CORE_ADDR page_addr)
{
    
    auto page_map_iterator = compile_memory_map.find(page_addr);

    if(page_map_iterator==compile_memory_map.end())
    {
        if (try_map_page(gdbarch, page_addr, 0) != 0)
        {
            page_map_t *new_page_map = new std::map<CORE_ADDR,CORE_ADDR>();
            compile_memory_map.insert({page_addr,new_page_map});
            return page_addr + PAGE_SIZE;
        }
        compile_memory_map.insert({page_addr,NULL});
        return page_addr;
    }

    page_map_t *page_map  = page_map_iterator->second;
    if(page_map == NULL)
    {
        return page_addr;
    }
    if(page_map->begin() != page_map->end())
    {
      return page_map->begin()->first;
    }
    return page_addr + PAGE_SIZE;
}

CORE_ADDR
next_available_address(gdbarch *gdbarch, CORE_ADDR base_address, int trampoline_size, int max_range)
{
    int page_size = PAGE_SIZE;
    CORE_ADDR candidate_address = base_address;
    CORE_ADDR page_addr;

    CORE_ADDR lower_bound;
    CORE_ADDR upper_bound;

    while(candidate_address - base_address < max_range) 
    {
        // fprintf_filtered(gdb_stdlog,"candidate 0x%lx base 0x%lx \n", candidate_address, base_address);
        page_addr = PAGE_ADDRESS(candidate_address);
        auto page_map_iterator = compile_memory_map.find(page_addr);
        

        if(page_map_iterator==compile_memory_map.end())
        {
            /* This page may be free. Try mapping  */
            if (try_map_page(gdbarch, page_addr, 0) != 0)
            {
                page_map_t *new_page_map = new std::map<CORE_ADDR,CORE_ADDR>();
                compile_memory_map.insert({page_addr,new_page_map});
                upper_bound = start_of_page(gdbarch, page_addr + page_size); // may map more pages than needed
                if (upper_bound < candidate_address + trampoline_size)
                {
                    /* There is not enough room in the next page 
                       to fit the end of the trampoline.  */
                    candidate_address = page_addr+page_size;
                    continue;
                }
                return candidate_address;
            }
            compile_memory_map.insert({page_addr,NULL});
            candidate_address += page_size;
            continue;
        }
        page_map_t *page_map = page_map_iterator->second;

        if(page_map == NULL)
        {
            /* This page is allocated by the program or cannot be accessed.  */
            candidate_address += page_size;
            continue;
        }
        // fprintf_filtered(gdb_stdlog,"page mapped\n");
        /* The page has already been mapped by this program. 
           Check for the next available chunk of the proper size.  */
        /* First entry after candidate_address.  */
        auto upper_entry = page_map->upper_bound(candidate_address);
        if(upper_entry == page_map->end())
        {
            if(candidate_address + trampoline_size > page_addr + page_size)
            {
              
              upper_bound = start_of_page(gdbarch, page_addr + page_size);
              // fprintf_filtered(gdb_stdlog,"Over end of page ub 0x%lx \n", upper_bound);
            }
            else
            {
              upper_bound = page_addr + page_size;
            }
            // fprintf_filtered(gdb_stdlog,"End of page\n");
        }
        else
        {
            upper_bound = upper_entry->first;
        }
        /* Check if there is enough room upwards */
        if (upper_bound >= candidate_address + trampoline_size)
        {
            // fprintf_filtered(gdb_stdlog,"Enough room\n");
            if(upper_entry == page_map->begin())
            {
                // fprintf_filtered(gdb_stdlog,"Start of page\n");
                lower_bound = page_addr;
            }
            else
            {
                lower_bound = (--upper_entry)->second;
            }
            if(lower_bound <= candidate_address)
            {
              // fprintf_filtered(gdb_stdlog,"Returning\n");
                return candidate_address;
            }
        }
        /* We check the next available address.  */
        if(upper_entry == page_map->end())
        {
            candidate_address = page_addr + page_size;
        }
        else
        {
            candidate_address = upper_entry->second;
        }
    }
  return 0;
}

void
allocate_trampoline(gdbarch *gdbarch, CORE_ADDR trampoline_address, int trampoline_size)
{
    CORE_ADDR page_addr = PAGE_ADDRESS(trampoline_address);
    auto page_map_iterator = compile_memory_map.find(page_addr);
    if (page_map_iterator == compile_memory_map.end())
    {
        error(_("Trying to allocate a trampoline on an unmapped page. \n\
This is not supposed to happen."));
    }
    page_map_t *page_map = page_map_iterator->second;
    // fprintf_filtered(gdb_stdlog, "Running check \n");
    /* Maybe check for availability.  */
    if (next_available_address(gdbarch, trampoline_address,trampoline_size,1)!=trampoline_address)
    {
        // fprintf_filtered(gdb_stdlog, "naa 0x%lx add 0x%lx \n", next_available_address(gdbarch, trampoline_address,trampoline_size,1), trampoline_address);
        error(_("Trying to allocate a trampoline on already allocated memory. \n\
This is not supposed to happen."));
    }
    page_map->insert({trampoline_address, trampoline_address + trampoline_size});
}

/* TMP Trashy */
static event_location_up
loc_from_pc(CORE_ADDR addr)
{
  char loc_string[50];
  sprintf(loc_string, "*0x%lx", addr);
  const char *loc_string2 = &loc_string[0];
  return string_to_event_location(&loc_string2, current_language);
}

Patch *get_patch(CORE_ADDR addr)
{
  return *(registered_patches.patches_overlapping(addr).begin());
}

CORE_ADDR
place_trampoline(gdbarch *gdbarch, Patch *patch, int trampoline_size)
{
    CORE_ADDR patched_addr = patch->patch_address;
    int *layout = patch->layout;
    const gdb_byte illegal_insn[14] = {6, 7, 14, 22, 23, 30, 31, 39, 47, 55, 63, 96, 97, 98};
    int32_t offset;
    gdb_byte *offset_array= (gdb_byte *) &offset;
    /* The offset we can add while only modifying the first original instruction.  */
    int max_range = 1<<(8*(layout[0]-1));
    if(max_range > (1<<30))
      max_range = 1<<30;
    
    if(layout[0]>=5)
    {
        // We have enough room to fit a full jump instruction
        CORE_ADDR tp_address = next_available_address(gdbarch, 
                      base_address(gdbarch, patched_addr), trampoline_size, 1<<30);
        allocate_trampoline(gdbarch, tp_address, trampoline_size);
        return tp_address;
    }

    // The instruction is too short, we need to work out where to place the trampoline to have the right jump offset
    target_read_memory(patched_addr+1, offset_array, 5-1);
    
    //set free lsbs to minimum
    //Here we try to leave all instructions but the first untouched.
    for(int i = 0; i < layout[0]-1 && i<4;i++)
    {
        offset_array[i]=(gdb_byte) 0;
    }
    CORE_ADDR candidate_address = patched_addr+offset+5;
    if(VALID_ADDRESS(candidate_address))
    {
        /* Try with this offset.  */
        CORE_ADDR next_address = next_available_address(gdbarch, candidate_address, trampoline_size, max_range);
        /* Check if next address is reachable modifying only the bytes from the first instruction.  */
        if(next_address-(candidate_address)<max_range)
        {
            allocate_trampoline(gdbarch, next_address, trampoline_size);
            return next_address;
        }
    }
    /* We need to modify more instructions than the first one,
       so we need to insert illegal instructions.  */
    /* First we only modify the first and last instructions.  */
    /* 5th byte of the jump is not the start of an instruction.  */
    // TMP : disable everything sigill related
    if(layout[4]<=0)
    {   int ill_insn_pos = -layout[4];
        patch->ill_insn_offset = ill_insn_pos-1;
        for(int i = 0; i < ILL_INSN_CNT; i++)
        {
            
            offset_array[ill_insn_pos-1]=illegal_insn[i];

            int32_t base_offset = next_available_address(gdbarch, base_address(gdbarch, patched_addr) - patched_addr - 5, trampoline_size, max_range);
            offset_array[3]=(gdb_byte)(base_offset>>(8*3));
            while((int8_t) offset_array[3]<MAX_INT8-1)
            {
                candidate_address = patched_addr+offset+5;
                if(VALID_ADDRESS(candidate_address))
                {
                    /* Try with this offset.  */
                    CORE_ADDR next_address = next_available_address(gdbarch, candidate_address, trampoline_size, max_range);
                    /* Check if next address is reachable modifying only the bytes from the first instruction.  */
                    if(next_address-(candidate_address)<max_range)
                    {
                        ill_insn_patches_kind.insert(
                          {patched_addr+ill_insn_pos, 10 + 5-ill_insn_pos});
                        create_breakpoint(gdbarch,
                              loc_from_pc(patched_addr+ill_insn_pos).get(),
                              NULL, 0, "", 1,
                              0, bp_breakpoint,
                              1<<30,
                               AUTO_BOOLEAN_TRUE,
                               &bkpt_breakpoint_ops,
                               0,
                               1,
                               1,
                               0);
                        allocate_trampoline(gdbarch, next_address, trampoline_size);
                        return next_address;
                    }
                }
                offset_array[3]+=1;
            }
        }
    }
    else
    {
        for(int i = 0; i < ILL_INSN_CNT; i++)
        {
            offset_array[4] = illegal_insn[i];
            candidate_address = patched_addr + offset + 5;
            if(VALID_ADDRESS(candidate_address))
            {
                /* Try with this offset.  */
                CORE_ADDR next_address = next_available_address(gdbarch, candidate_address, trampoline_size, max_range);
                /* Check if next address is reachable modifying only the bytes from the first instruction.  */
                if(next_address-(candidate_address)<max_range)
                {
                    /* allocate breakpoint of kind 11 at address candidate_address.  */
                    ill_insn_patches_kind.insert({patched_addr + 4, 10 + 1});
                    create_breakpoint(gdbarch,
                              loc_from_pc(patched_addr + 4).get(),
                              NULL, 0, "", 1,
                              0, bp_breakpoint,
                              1<<30,
                               AUTO_BOOLEAN_TRUE,
                               &bkpt_breakpoint_ops,
                               0,
                               1,
                               1,
                               0);
                    allocate_trampoline(gdbarch, next_address, trampoline_size);
                    return next_address;
                }
            }
        }
    }
    return 0;
}

int
patch_cmd_kind(int default_val, CORE_ADDR address)
{
  auto iterator = ill_insn_patches_kind.find(address);
  if(iterator == ill_insn_patches_kind.end())
    return default_val;
  else
  {
    return iterator->second;
  }

}
/* Analyze the layout of instructions around patched_addr and determines
   where to place the trampoline accordingly
     layout[i] = n>0 : insn of length n starts at position i.
     layout[i] = n <= 0 : byte at pos i is part of instruction starting at pos -n. */
void
analyse_layout(gdbarch *gdbarch, Patch *patch)
{
  CORE_ADDR current_address = patch->patch_address;
  patch_list overlapping = registered_patches.patches_overlapping(current_address + 4);
  int next_patch_distance = 5;
  int insn_length;

  if(!(overlapping.empty()))
    {
      Patch *first_overlap = overlapping.front();
      next_patch_distance = first_overlap->patch_address - patch->patch_address;
      for(int j = next_patch_distance; j<5; j++)
      {
        patch->layout[j]= first_overlap->layout[j-next_patch_distance];
      }
    }
  
  int byte_position = 0;
  while (byte_position<next_patch_distance)
  {
    insn_length = gdb_insn_length(gdbarch, current_address);
    patch->layout[byte_position] = insn_length;
    for(int j=1; j<insn_length && j+byte_position<5 ;j++)
    {
        patch->layout[byte_position+j] = -byte_position;
    }
    current_address += insn_length;
    byte_position+=insn_length;
  }
}

static CORE_ADDR
build_compile_trampoline (struct gdbarch *gdbarch,
                          Patch *patch,
                          CORE_ADDR return_address)
{
  CORE_ADDR insn_addr = patch->patch_address;
  /* Allocate memory for the trampoline in the inferior.  */
  analyse_layout(gdbarch, patch);

  CORE_ADDR trampoline = place_trampoline(gdbarch, patch, TP_MAX_SIZE);

  if (trampoline == 0)
  {
    return 0;
  }
  /* Build trampoline.  */
  gdb_byte trampoline_instr[TP_MAX_SIZE];
  int trampoline_size
      = gdbarch_fill_trampoline_buffer (gdbarch, trampoline_instr, patch->comp_module);

  gdb_assert(trampoline_size<TP_MAX_SIZE);

  /* Copy content of trampoline_instr to inferior memory.  */
  target_write_memory (trampoline, trampoline_instr, trampoline_size);

  /* Relocate replaced instruction */
  CORE_ADDR trampoline_end = trampoline + trampoline_size;
  while(insn_addr<return_address)
  {
    /* offset >=0 && offset < jump_insn_size */
    int original_offset = insn_addr - patch->patch_address;
    patch->relocated_insn_offset[original_offset]= (int) (trampoline_end-trampoline);
    gdbarch_relocate_instruction (gdbarch, &trampoline_end, insn_addr);
    insn_addr += gdb_insn_length(gdbarch, insn_addr);
  }
  
  gdb_assert(trampoline_end - trampoline + gdbarch_jmp_insn_length(gdbarch, 0) < TP_MAX_SIZE);
  
  /* Jump back to return address.  */
  gdbarch_patch_jump(gdbarch, trampoline_end, return_address);

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
    
  Patch *new_patch = new Patch(compile_module, insn_addr);
  new_patch->original_insn_length = gdb_insn_length(gdbarch, insn_addr);
  target_read_memory(insn_addr, new_patch->original_insn, new_patch->original_insn_length);

  CORE_ADDR trampoline_address = build_compile_trampoline (
      gdbarch, new_patch, return_address);
  
  if (trampoline_address == 0)
  {
      fprintf_filtered(gdb_stderr,
        "Unable to build a trampoline.\n");
      /* Free unused memory */
      unlink (compile_module->source_file);
      xfree (compile_module->source_file);
      unlink (objfile_name (compile_module->objfile));
      xfree (compile_module);
      return;
  }

  /* Patch in the jump to the trampoline.  */
  bool success = gdbarch_patch_jump (gdbarch, insn_addr, trampoline_address);
  if (!success)
  {
    fprintf_filtered(gdb_stderr,
"Unable to insert the code at the given location.\n\
Make sure the instruction is long enough \n\
to be replaced by a jump instruction.\n");
  }
  else
  {
    /* Register patch.  */
    int offset = trampoline_address - insn_addr - 5;
    memcpy(new_patch->offset, &offset, 4);
    registered_patches.insert(new_patch);
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
      error ("Missing the second argument for the patch file command.");
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