#include <stdbool.h>
#include <stddef.h>

#include "../include/core.h"

static struct ef_tree *ef_root;
static struct glist *cap_pkts;
static struct glist *single_cap_pkt;

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

static status_val filter_rec(struct ef_tree *node, const u_char *data, u_char *args, const struct pcap_pkthdr *header, unsigned read_off)
{
    status_val status;
    const unsigned base_read_off = read_off;

    if (node->lvl) { //skiping root root node
	status = derive_packet(single_cap_pkt, node, data, header->caplen, &read_off); //trying to split data to packet fields
	if (status) {
	    read_off = base_read_off; //reverting read offset
	    LOGF(L_DEBUG, STATUS_NOT_FOUND, "Packet dropped for %s\n", node->flt->filter->packet_tag);
	    return STATUS_NOT_FOUND; //if this filter fails, then all children filter must fail
	}
	
	//TODO call validateion callback here 
	
    }
    
    if (node->chld) { //desending down into first child filter if it exists
	filter_rec(node->chld, data, args, header, read_off); //persist filtering on failure
    }

    if (node->next) { // going to sibling filter
	filter_rec(node->next, data, args, header, read_off); //persist filtering on failure
    }   

    return STATUS_OK;
}

status_val core_init()
{
    cap_pkts = glist_new(CAP_PKTS);
    if (!cap_pkts) {
	LOG(L_CRIT, STATUS_OMEM);
	return STATUS_OMEM;
    }

    glist_set_free_cb(cap_pkts, (void(*)(void*))packet_free);

    single_cap_pkt = glist_new(64);
    if (!single_cap_pkt) {
	LOG(L_CRIT, STATUS_OMEM);
	glist_free(cap_pkts);
	return STATUS_OMEM;
    }
    status_val status;
    status = build_ef_tree();
    if (status) {
	LOG(L_CRIT, status);
	glist_free(single_cap_pkt);
	glist_free(cap_pkts);
	return status;
    }

    return status;
}


void core_filter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    (void)args;
    (void)header;

    glist_clear_shallow(single_cap_pkt); //clearing old single packet capture list

    status_val status = filter_rec(ef_root, packet, args, header, 0);
    (void)status; //TODO fix

    if (glist_copy_to(single_cap_pkt, cap_pkts)) { //copying elements ot main captured packet list
	LOG(L_ERR, STATUS_OMEM);
    }



}

void core_destroy()
{
    glist_free_shallow(single_cap_pkt); //do not need to free containing elements; just unlinking
    glist_free(cap_pkts);
    ef_tree_free(ef_root);
}
