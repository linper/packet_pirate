#include <stdlib.h>

#include "../../../../include/utils.h"
#include "../../../../include/glist.h"
#include "../../../../include/ef_tree.h"
#include "../../../../include/ext_filter.h"
#include "../../../../include/filter.h"

static struct f_entry icmpv6_packet[] = {
/*  TAG 				LENGTH 		MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"icmpv6_type", 	E_LEN(1), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ivmpv6_code", 	E_LEN(1), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"icmpv6_cksum", 	E_LEN(2), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"icmpv6_msg", 		E_PAC_OFF_OF("icmpv6_type", "ipv6_pld_len"),8,0,ERF_BIN,EWF_HEXDUMP},
}; 

static vld_status validate_icmpv6(struct packet *p, struct ef_tree *node)
{
	(void)p;
	(void)node;

	struct p_entry *pe;

	struct packet *pp = get_packet_by_tag(p, "ipv6");
	if (!pp) {
		return VLD_DROP;
	}
	
	pe = PENTRY(pp, "ipv6_n_head");
	if (pe->conv_data.ulong != 58) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

static struct filter icmpv6_filter = {
	.parent_tag = "ipv6",
	.packet_tag = "icmpv6",
	.validate = validate_icmpv6,
	.entries = icmpv6_packet,
	.n_entries = FILTER_LEN(icmpv6_packet),
};

INIT_FILTER(icmpv6_filter)

