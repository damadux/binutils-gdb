#ifndef PATCH_H
#define PATCH_H


#include <map>
#include <list>

#define MAX_INSN_LEN 15

/* A Patch represents an addition to the original binary. */
class Patch
{
private:
    struct munmap_list *munmap_list_head;

public:
    CORE_ADDR patch_address;

    CORE_ADDR trampoline_address;

    int original_insn_length;
    gdb_byte original_insn[MAX_INSN_LEN];

    bool active;

    struct compile_module *comp_module;

    Patch(compile_module *module, CORE_ADDR addr)
    {
        comp_module = module;
        patch_address = addr;
        active = TRUE;
    }

    ~Patch()
    {
        /* maybe call do_module_cleanup */
        unlink (comp_module->source_file);
        xfree (comp_module->source_file);
        unlink (objfile_name (comp_module->objfile));
        delete comp_module->munmap_list_head;
        xfree (comp_module);
    }
};

typedef std::list<Patch *> patch_list;

/* A class that stores all patches on an inferior.  */
class PatchMap
{
    std::map<CORE_ADDR, patch_list*> all_patches;

    public:
        /* Add a new patch.  */
        void
        insert(Patch *new_patch)
        {
            CORE_ADDR patch_address = new_patch->patch_address;
            if(all_patches.find(patch_address)==all_patches.end())
            {
                patch_list *new_list = new patch_list();
                new_list->push_front(new_patch);
                all_patches.insert({patch_address, new_list});
            }
            else
            {
                all_patches[patch_address]->push_front(new_patch);
            }
        };

        /* Return a pointer to the list of patches at a specific address.  */
        patch_list *
        patches_at_address(CORE_ADDR address)
        {
            auto patch_iterator = all_patches.find(address);
            if(patch_iterator!=all_patches.end())
            {
                return patch_iterator->second;
            }
            return NULL;
        }

        /* Return the list of patches overlapping a specific address.  */
        patch_list 
        patches_overlapping(CORE_ADDR address)
        {
            patch_list overlapping_patches;
            auto patch_iterator = all_patches.lower_bound(address - 4);
            patch_list *patches_to_append;
            while(patch_iterator!=all_patches.end() 
                    && patch_iterator->first <= address)
            {
                patches_to_append = patch_iterator->second;
                /* Copy the patches into the return list.  */
                overlapping_patches.insert(overlapping_patches.end(), 
                                patches_to_append->begin(), 
                                patches_to_append->end());
            }
            return overlapping_patches;
        }
};

#endif