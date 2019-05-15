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

/* A set of patches that can be searched by index or address.  */
class PatchVector
{
public:
    PatchVector(){};
    std::vector<Patch *> patches;
    std::vector<bool> active;
    int add(Patch *patch)
    {
        patches.push_back(patch);
        active.push_back(true);
        return patches.size();
    }
    
    Patch *find_index(int i)
    {
        if(active[i])
        {
            return patches[i];
        }
        return NULL;
    }

    int remove(int i)
    {
        if(active[i])
        {
            active[i]=false;
            return 0;
        }
        return -1;
    }

    /* returned vector needs to be freed */ 
    std::vector<Patch *> *find_address(CORE_ADDR address)
    {
        std::vector<Patch *> *patches_found = new std::vector<Patch *>();
        int i = 0;
        auto it = patches.begin();
        for(;it!= patches.end();it++){
            if((*it)->address == address)
            {
                if(active[i]){
                    patches_found->push_back(*it);
                }
                i++;
            }
        }
        return patches_found;
    }


};