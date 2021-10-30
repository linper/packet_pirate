#include <stdbool.h>

#include "../include/core.h"

static struct ef_tree *ef_root;

static status_val build_ef_tree()
{
    status_val ret = STATUS_BAD_INPUT;
    struct ext_filter *ef = NULL;
    if (!(ef_root = ef_tree_base())) {
	return STATUS_OMEM;	    
    }

    bool found = true;
    while(found) {
        found = false;

        for (struct filter **f = filter_arr; *f; f++) {
            if (ef_tree_contains_by_tag(ef_root, (*f)->packet_tag) && /* does not contain packet */\
		    (!*(*f)->parent_tag || 				/* is link layer packet */\
		     !ef_tree_contains_by_tag(ef_root, (*f)->parent_tag))) { /*contains parent packet*/ 
                if (!(ef = ext_filter_new(*f))) {
                    ret = STATUS_OMEM;
                    goto err;
                }

                if (ef_tree_put(ef_root, ef)) {
                    ext_filter_free(ef);
                    ret = STATUS_OMEM;
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

    build_ef_tree();
    /*struct filter **p_filter_arr;*/

    /*collect_packets(&p_filter_arr);*/


    //todo register filters to tree structure


    //todo converting filter_arr to tree structure

    return 0;
}

status_val core_filter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;



    return 0;
}
