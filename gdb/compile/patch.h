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

    Patch(munmap_list *mmp_list, CORE_ADDR addr)
    {
        munmap_list_head = mmp_list;
        address = addr;
    }

    ~Patch()
    {
        delete munmap_list_head;
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

#endif /* PATCH_H */