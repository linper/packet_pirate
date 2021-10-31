#include <stdbool.h>

#include "../include/core.h"

static struct ef_tree *ef_root;

static status_val build_ef_tree()
{
    status_val ret = STATUS_BAD_INPUT;
    struct ext_filter *ef = NULL;
    if (!(ef_root = ef_tree_base())) {
	LOG(L_CRIT, STATUS_OMEM);
	return STATUS_OMEM;	    
    }

    bool found = true;
    while(found) { //till all filters reachable from root are added
        found = false;

        for (struct filter **f = filter_arr; *f; f++) {
	    //checking if parent filter is in the tree and curent is not
            if (ef_tree_contains_by_tag(ef_root, (*f)->packet_tag) && /*does not contain filter*/\
		    (!*(*f)->parent_tag || 				/*is link layer filter*/\
		     !ef_tree_contains_by_tag(ef_root, (*f)->parent_tag))) { /*contains parent filter*/ 
		//now we know that current filter can be added to tree
                if (!(ef = ext_filter_new(*f))) { //createing new extended filter
                    ret = STATUS_OMEM;
		    LOG(L_CRIT, ret);
                    goto err;
                }

                if ((ret = ef_tree_put(ef_root, ef))) { //adding new filter to filter tree
		    LOG(L_CRIT, ret);
                    ext_filter_free(ef);
                    goto err;
                }
                found = true;
            }
        }
    }

    return STATUS_OK;
err:
    ef_tree_free(ef_root);
    return ret;
}

status_val core_init()
{
    status_val status;
    status = build_ef_tree();
    if (status) {
	LOG(L_CRIT, status);
    }
    /*struct filter **p_filter_arr;*/

    /*collect_packets(&p_filter_arr);*/


    //todo register filters to tree structure


    //todo converting filter_arr to tree structure

    return status;
}

status_val core_filter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;



    return STATUS_OK;
}
