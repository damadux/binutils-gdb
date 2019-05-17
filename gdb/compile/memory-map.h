#ifndef MEMORY_MAP_H
#define MEMORY_MAP_H

#include <map>

#define PAGE_SIZE 0x1000
#define PAGE_ADDRESS(a) ((a/PAGE_SIZE) * PAGE_SIZE)

/* Is the page containing addr available ? If so map it.  */
static CORE_ADDR
can_mmap(gdbarch *gdbarch, CORE_ADDR addr)
{
  const int prot = GDB_MMAP_PROT_READ | GDB_MMAP_PROT_WRITE | GDB_MMAP_PROT_EXEC;
  
  CORE_ADDR mmapped_area = gdbarch_infcall_mmap(gdbarch, PAGE_ADDRESS(addr), PAGE_SIZE, prot);
  
  if(mmapped_area == PAGE_ADDRESS(addr))
  {
    return mmapped_area;
  }
  gdbarch_infcall_munmap(gdbarch, mmapped_area, PAGE_SIZE);
  return (CORE_ADDR) 0;
}

typedef std::map<CORE_ADDR, CORE_ADDR>  page_map_t;

class amd64_MemoryMap
{
  private:
    std::map<CORE_ADDR, page_map_t *> mem_map;
  
  public:

    CORE_ADDR
    allocate_precise(gdbarch *gdbarch, CORE_ADDR addr, int size)
    {
      CORE_ADDR page_address = PAGE_ADDRESS(addr);
      CORE_ADDR lower_bound = page_address;
      CORE_ADDR upper_bound = page_address + PAGE_SIZE;

      if (mem_map.find(page_address) != mem_map.end())
      {
        page_map_t *page_map = mem_map[page_address];
        if (page_map == NULL)
        {
          /* This page cannot be mapped.  */
          return (CORE_ADDR) 0;
        }
        /* First element after addr */
        auto it = page_map->upper_bound(addr); 
        
        /* No allocated interval after addr.  */
        if(it == page_map->end())
        {
          auto rit = page_map->rbegin();
          lower_bound = rit->second;
        }
        else
        {
          upper_bound = it->first;
          lower_bound = --it->second;
          if(lower_bound > upper_bound)
          {
            /* There was no interval before addr.  */
            lower_bound = page_address;
          }
        }

        if(lower_bound <= addr && upper_bound > addr + size)
        {
          page_map->insert({addr, addr + size});
          return addr;
        }
        /* Memory is already used by another jump pad.  */
        return 0;
      }

      if(can_mmap(gdbarch, addr))
      {
        CORE_ADDR next_page = PAGE_ADDRESS(addr) + PAGE_SIZE;
        if(addr + size > next_page)
        {
          /* The trampoline overlaps two pages.  */
          /* Either the second page is already mapped or not.  */
          if (mem_map.find(next_page) != mem_map.end())
          {
            page_map_t *page_map = mem_map[page_address+PAGE_SIZE];

            if (page_map == NULL)
            {
              /* The next page is not mappable.  */
              return 0;
            }
            auto it = page_map->begin();
            upper_bound = it->first;
            if(addr + size < upper_bound)
            {
              mem_map[next_page]->insert({next_page, addr + size});
            }
          }
          if (can_mmap(gdbarch, next_page))
          {
            mem_map.insert({page_address, new std::map<CORE_ADDR, CORE_ADDR>()});
            mem_map[page_address]->insert({addr,next_page});
            
            mem_map.insert({next_page, new std::map<CORE_ADDR, CORE_ADDR>()});
            mem_map[next_page]->insert({next_page, addr + size});
          }
          else
          {
            mem_map.insert({next_page, NULL});
            gdbarch_infcall_munmap(gdbarch, page_address, PAGE_SIZE);
          }
          
        }
        mem_map.insert({page_address, new std::map<CORE_ADDR, CORE_ADDR>()});
        mem_map[page_address]->insert({addr, addr + size});
        return addr;
      }
      return (CORE_ADDR) 0;
    }

    /* Allocate a trampoline of size ''size''
       at the next available address after ''addr''.  */
    CORE_ADDR
    allocate_after(gdbarch *gdbarch, CORE_ADDR addr, int size)
    {
      int pages_tried = 0;
      int max_pages=20;
      CORE_ADDR page_address = PAGE_ADDRESS(addr);
      while(pages_tried < max_pages)
      {
        /* Here we try to stack trampolines on next to the other.
           We only add a trampoline at the end of the allocated portion
           of a page.  */
        if (mem_map.find(page_address) != mem_map.end())
        {
          page_map_t *page_map = mem_map[page_address];
          if (page_map == NULL)
          {
            /* We already got a failed mmap call at that address.  */
            pages_tried += 1;
            page_address += PAGE_SIZE;
            continue;
          }
          auto rit = page_map->rbegin();
          CORE_ADDR lower_bound = rit->second;
          /* This is the last page, so the upper bound is the start of the next */
          if(lower_bound + size > page_address + PAGE_SIZE)
          {
            /* We don't place trampolines overlapping two pages in this case 
               to simplify.  */
            pages_tried +=1;
            page_address+=PAGE_SIZE;
            continue;
          }
          mem_map[page_address]->insert({lower_bound, lower_bound + size});
          return lower_bound;
        }
        if(can_mmap(gdbarch, page_address))
        {
          mem_map.insert({page_address, new std::map<CORE_ADDR, CORE_ADDR>()});
          mem_map[page_address]->insert({page_address, page_address + size});
          return page_address;
        }
        else
        {
          mem_map.insert({page_address, NULL});
          pages_tried += 1;
          page_address += PAGE_SIZE;
        }
      }
      error(_("ERROR : Unable to map a new region."));
    }
};


#endif /* MEMORY_MAP_H */