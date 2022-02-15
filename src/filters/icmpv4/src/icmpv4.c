#include "../include/icmpv4.h"

static struct f_entry icmpv4_packet[] = {
/*  TAG 				LENGTH 		MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"icmpv4_type", 	E_LEN(1), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ivmpv4_code", 	E_LEN(1), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"icmpv4_cksum", 	E_LEN(2), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"icmpv4_rest", 	E_LEN(4), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
}; 

static vld_status validate_icmpv4(struct packet *p, struct ef_tree *node)
{
	(void)p;
	
	struct p_entry *pe;
	struct ef_tree *pn = node->par;

	struct packet *pp = get_packet_by_tag(pc.single_cap_pkt, "ipv4");
	if (!pp) {
		return VLD_DROP;
	}
	
	//icmpv4 protocol is indicated as 1 in ipv4 packet
	pe = PENTRY(pn, pp, "ipv4_proto");
	if (pe->conv_data.ulong != 1) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

struct filter icmpv4_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "icmpv4",
	.validate = validate_icmpv4,
	.entries = icmpv4_packet,
	.n_entries = FILTER_LEN(icmpv4_packet),
};

