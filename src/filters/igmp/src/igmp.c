#include "../include/igmp.h"

static struct f_entry igmp_packet[] = {
/*  TAG 			LENGTH 			MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"igmp_type", 	E_LEN(8), 		1,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"igmp_mrt", 	E_LEN(8), 		1,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"igmp_cksum", 	E_LEN(2), 		8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"igmp_addr", 	E_LEN(4), 		8,	0, 			ERF_UINT_BE, 	EWF_DEC_DT},
	{"igmp_rest", 	E_PAC_OFF_OF("ipv4_ver", "ipv4_len"), 8, EF_OPT, ERF_BIN, EWF_RAW},
}; 

static vld_status validate_igmp(struct packet *p, struct ef_tree *node)
{
	(void)p;
	struct p_entry *pe;

	struct packet *pp = get_packet_by_tag(p, "ipv4");
	if (!pp) {
		return VLD_DROP;
	}
	
	//igmp protocol is indicated as 2 in ipv4 packet
	pe = PENTRY(pp, "ipv4_proto");
	if (pe->conv_data.ulong != 2) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

struct filter igmp_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "igmp",
	.validate = validate_igmp,
	.entries = igmp_packet,
	.n_entries = FILTER_LEN(igmp_packet),
};

INIT_FILTER(igmp_filter)

