#include <stdlib.h>

#include "../../../../include/utils.h"
#include "../../../../include/glist.h"
#include "../../../../include/ef_tree.h"
#include "../../../../include/ext_filter.h"
#include "../../../../include/filter.h"

static struct f_entry ipv4_packet[] = {
/*  TAG 			LENGTH 			MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"ipv4_ver", 	E_LEN(4), 		1,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_ihl", 	E_LEN(4), 		1,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_dscp", 	E_LEN(6), 		1,	0, 			ERF_UINT_BE, 	EWF_HEX_STR},
	{"ipv4_ecn", 	E_LEN(2), 		1,	0, 			ERF_UINT_BE, 	EWF_HEX_STR},
	{"ipv4_len", 	E_LEN(2), 		8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_id", 	E_LEN(2), 		8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_flags", 	E_LEN(2), 		1, 	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_frag_off", E_LEN(14), 	1, 	0, 			ERF_UINT_BE, 	EWF_HEX_STR},
	{"ipv4_ttl", 	E_LEN(1), 		8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_proto", 	E_LEN(1), 		8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_cksum", 	E_LEN(2), 		8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"ipv4_src", 	E_LEN(4), 		8,	0, 			ERF_UINT_BE, 	EWF_DEC_DT},
	{"ipv4_dest", 	E_LEN(4), 		8,	0, 			ERF_UINT_BE, 	EWF_DEC_DT},
	{"ipv4_opt", 	E_PAC_OFF_OF("ipv4_ver", "ipv4_ihl"), 32, EF_OPT, ERF_BIN, EWF_RAW},
	{"ipv4_pld", 	E_PAC_OFF_OF("ipv4_ver", "ipv4_len"), 8, EF_PLD_REG, ERF_BIN, EWF_RAW},
}; 

static vld_status validate_ipv4(struct packet *p, struct ef_tree *node)
{
	struct p_entry *pe;

	//vhl is always equal to 4
	pe = PENTRY(p, "ipv4_ver");
	if (pe->conv_data.ulong != 4) {
		return VLD_DROP;
	}

	//ihl is always [5; 15]
	pe = PENTRY(p, "ipv4_ihl");
	if (pe->conv_data.ulong < 5) {
		return VLD_DROP;
	} else if (pe->conv_data.ulong > 5) {
		pe = PENTRY(p, "ipv4_opt");
		//if ihl is greater than 5, options must exist
		if (!pe->raw_len) {
			return VLD_DROP;
		}
	}

	//total length is always [20; 65535]
	pe = PENTRY(p, "ipv4_len");
	if (pe->conv_data.ulong < 20) {
		return VLD_DROP;
	}

	//MSB (evil bit) is always 0
	pe = PENTRY(p, "ipv4_flags");
	if (pe->conv_data.ulong & 0x4) {
		return VLD_DROP;
	}

	//hinting optimizes filtering
	pe = PENTRY(p, "ipv4_proto");
	switch (pe->conv_data.ulong) {
	case 1:
		HINT(node, "icmpv4");
		break;
	case 2:
		HINT(node, "igmp");
		break;
	case 6:
		HINT(node, "tcp");
		break;
	case 17:
		HINT(node, "udp4");
		break;
	}

	return VLD_PASS;
}

static struct filter ipv4_filter = {
	.parent_tag = "ethernet",
	.packet_tag = "ipv4",
	.validate = validate_ipv4,
	.entries = ipv4_packet,
	.n_entries = FILTER_LEN(ipv4_packet),
};
	
INIT_FILTER(ipv4_filter)

