#include <stdlib.h>

#include "../../../../include/utils.h"
#include "../../../../include/glist.h"
#include "../../../../include/ef_tree.h"
#include "../../../../include/ext_filter.h"
#include "../../../../include/filter.h"

static struct f_entry arp_packet[] = {
/*  TAG 			LENGTH 					MUL	FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"arp_htype", 	E_LEN(2), 				8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_ptype", 	E_LEN(2), 				8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_hlen", 	E_LEN(1), 				8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_plen", 	E_LEN(1), 				8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_oper", 	E_LEN(4), 				8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_sha", 	E_LEN_OF("arp_hlen"), 	8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_spa", 	E_LEN_OF("arp_plen"), 	8,	0,		ERF_UINT_BE, 	EWF_UINT},
	{"arp_tha", 	E_LEN_OF("arp_hlen"), 	8,	0, 		ERF_UINT_BE, 	EWF_UINT},
	{"arp_tpa", 	E_LEN_OF("arp_plen"), 	8,	0, 		ERF_UINT_BE, 	EWF_UINT},
}; 

static vld_status validate_arp(struct packet *p, struct ef_tree *node)
{
	(void)p;
	(void)node;
	
	struct p_entry *pe;

	struct packet *pp = get_packet_by_tag(p, "ethernet");
	if (!pp) {
		return VLD_DROP;
	}
	
	//arp protocol is indicated as 0x0806 in eternet packet
	//if hinting is properly done, than this is not nessery
	pe = PENTRY(pp, "eth_type");
	if (pe->conv_data.ulong != 0x0806) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

static struct filter arp_filter = {
	.parent_tag = "ethernet",
	.packet_tag = "arp",
	.validate = validate_arp,
	.entries = arp_packet,
	.n_entries = FILTER_LEN(arp_packet),
};

INIT_FILTER(arp_filter)

