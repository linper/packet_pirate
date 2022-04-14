#include "../include/ipv6.h"

static struct f_entry ipv6_packet[] = {
/*  TAG 				LENGTH 			MUL		FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"ipv6_ver", 		E_LEN(4), 		1,		0, 		ERF_UINT_BE, 	EWF_UINT},
	{"ipv6_traf_cl", 	E_LEN(8), 		1,		0, 		ERF_UINT_BE, 	EWF_UINT},
	{"ipv6_flow", 		E_LEN(20), 		1,		0, 		ERF_UINT_BE, 	EWF_HEXDUMP},
	{"ipv6_pld_len", 	E_LEN(2), 		8,		0, 		ERF_UINT_BE, 	EWF_UINT},
	{"ipv6_n_head", 	E_LEN(1), 		8,		0, 		ERF_UINT_BE, 	EWF_UINT},
	{"ipv6_hop_lim", 	E_LEN(1), 		8,		0, 		ERF_UINT_BE, 	EWF_UINT},
	{"ipv6_src", 		E_LEN(16), 		8,		0, 		ERF_UINT_BE, 	EWF_HEX_DT},
	{"ipv6_dest", 		E_LEN(16), 		8,		0, 		ERF_UINT_BE, 	EWF_HEX_DT},
	{"ipv4_pld", 		E_LEN_OF("ipv6_pld_len"), 8, EF_PLD_REG, ERF_BIN, EWF_RAW},
}; 

static vld_status validate_ipv6(struct packet *p, struct ef_tree *node)
{
	struct p_entry *pe;

	//version is always equal to 6
	pe = PENTRY(node, p, "ipv6_ver");
	if (pe->conv_data.ulong != 6) {
		return VLD_DROP;
	}

	//hinting optimizes filtering
	pe = PENTRY(node, p, "ipv6_n_head");
	switch (pe->conv_data.ulong) {
	case 58:
		HINT(node, "icmpv6");
		break;
	}

	return VLD_PASS;
}

struct filter ipv6_filter = {
	.parent_tag = "ethernet",
	.packet_tag = "ipv6",
	.validate = validate_ipv6,
	.entries = ipv6_packet,
	.n_entries = FILTER_LEN(ipv6_packet),
};

INIT_FILTER(ipv6_filter)

