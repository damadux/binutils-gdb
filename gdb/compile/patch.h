#ifndef PATCH_H
#define PATCH_H
#include "compile-object-load.h"

/* A Patch represents an addition to the original binary. */
class Patch
{
private:
    struct munmap_list *munmap_list_head;

public:
    CORE_ADDR trampoline_address;
    CORE_ADDR address;
    CORE_ADDR relocated_insn_address;

    Patch(munmap_list *mmp_list, CORE_ADDR addr) 
        : munmap_list_head(mmp_list), address(addr) {}

    ~Patch()
    {
        delete munmap_list_head;
    }
};

struct active_patch
{
    Patch *patch;
    bool active;
};

/* A set of patches that can be searched by index or address.  */
class PatchVector
{
public:
    std::vector<struct active_patch> patches;

    int add(Patch *patch)
    {
        patches.push_back({patch,true});
        return patches.size();
    }
    
    Patch *find_index(int i)
    {
        if(i<patches.size() && patches[i].active)
        {
            return patches[i].patch;
        }
        return NULL;
    }

    bool remove(int i)
    {
        if(i<patches.size() && patches[i].active)
        {
            patches[i].active=false;
            delete patches[i].patch;
            patches[i].patch = NULL;
            return true;
        }
        return false;
    }

    std::vector<Patch *> find_address(CORE_ADDR address)
    {
        std::vector<Patch *> patches_found;
        auto it = patches.begin();
        for(;it!= patches.end();it++){
            if(it->active)
            {
                if(it->patch->address == address)
                {
                    patches_found.push_back(it->patch);
                }
            }
        }
        return patches_found;
    }

    void reset()
    {
        auto it = patches.begin();
        for(;it!= patches.end();it++){
            if(it->active)
            {
                delete it->patch;
            }
        }
        patches.clear();
    }
};

#endif  /* PATCH_H */