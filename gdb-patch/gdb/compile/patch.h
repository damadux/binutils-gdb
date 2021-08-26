#ifndef PATCH_H
#define PATCH_H

#include "defs.h"
#include "compile-object-load.h"

/* A Patch represents an addition to the original binary. */
class Patch
{
private:
    struct munmap_list *munmap_list_head;

public:
    CORE_ADDR trampoline_address;
    CORE_ADDR address;
    /* this is a fix offset to trampoline, it could be resolved statically */
    CORE_ADDR relocated_insn_address;
    gdb_byte original_insn[6];

    Patch(munmap_list *mmp_list, CORE_ADDR addr)
    {
        munmap_list_head = mmp_list;
        address = addr;
    }
    /* FIXME : Load / store does not support storing the original instruction */
    Patch(const char *load_string)
    {
        const char *next;
        address = (CORE_ADDR) strtol(load_string, (char **) &next,10);
        if(*next == ' ')
        {
            next++;
        }
        relocated_insn_address = (CORE_ADDR) strtol(next,NULL,10);
        munmap_list_head = NULL;
    }

    void store(char *store_string)
    {
        sprintf(store_string,"%lu %lu\n",address, relocated_insn_address);
    }

    void read_original_insn(gdbarch *gdbarch, int offset)
    {
        // int len = gdb_insn_length(gdbarch, address);
        // /* We keep all the instructions intersecting the future jump */ 
        // /* Needed when the original instruction is not 5 bytes long*/
        // while(len < 5)
        // {
        //     len+=gdb_insn_length(gdbarch, address + len);
        // }
        target_read_memory(address+offset, original_insn+offset, 6-offset);
    }
    void offset_address()
    {
        address++;
        memmove(original_insn, original_insn+1, 5);
    }

    ~Patch()
    {
        if (munmap_list_head != NULL)
        {
            delete munmap_list_head;
        }
    }
};

struct patch_info
{
    Patch *patch;

    bool active;
};

/* A set of patches that can be searched by index or address.  */
class PatchVector
{
public:
    std::vector<patch_info> patches;
    
    int add(Patch *patch)
    {
        struct patch_info info;
        info.patch = patch;
        info.active = true;
        patches.push_back(info);
        return patches.size();
    }
    
    Patch *find_index(int i)
    {
        if(patches[i].active)
        {
            return patches[i].patch;
        }
        return NULL;
    }

    void remove(int i)
    {
        patches[i].active=false;
    }

    /* returned vector needs to be freed */ 
    std::vector<Patch *> find_address(CORE_ADDR address)
    {
        std::vector<Patch *> patches_found;
        auto it = patches.begin();
        for(;it!= patches.end();it++){
            if((it->patch)->address == address)
            {
                if(it->active){
                    patches_found.push_back(it->patch);
                }
            }
        }
        return patches_found;
    }
    void store(const char *path)
    {
        FILE *file = fopen(path,"w");
        auto it = patches.begin();
        char line[128];
        for(;it!= patches.end();it++){
            (it->patch)->store(line);
            fputs(line,file);
        }
        fclose(file);
    }
    void load(const char *path)
    {
        FILE *file = fopen(path,"r");
        if ( file != NULL )
        {
            char line [ 128 ];
            while ( fgets ( line, sizeof(line), file ) != NULL ) 
            {
                Patch *p = new Patch(line);
                struct patch_info info;
                info.patch = p;
                info.active = true;
                patches.push_back(info);
            }
            fclose ( file );
        }
    }
};

#endif /* PATCH_H */