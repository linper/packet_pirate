#include "../include/ethernet.h"

static struct f_entry ethernet_packet[] = {
/*  TAG 			LENGTH 		MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"eth_dhost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},
	{"eth_shost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},
	{"eth_type", 	E_LEN(2), 	8,	0, 			ERF_UINT_BE, 	EWF_UINT},
	{"eth_pld", 	E_UNKN, 	8,	EF_PLD_REG, ERF_BIN,		EWF_RAW},
}; 

static vld_status validate_eth(struct packet *p, struct ef_tree *node)
{
	struct p_entry *pe = PENTRY(node, p, "eth_type");
	switch (pe->conv_data.ulong) {
	case 0x0800:
		HINT(node, "ipv4");
		break;
	case 0x0806:
		HINT(node, "arp");
		break;
	}

	return VLD_PASS;
}

struct filter ethernet_filter = {
	.parent_tag = {0},
	.packet_tag = "ethernet",
	.validate = validate_eth,
	.entries = ethernet_packet,
	.n_entries = FILTER_LEN(ethernet_packet),
};
	
INIT_FILTER(ethernet_filter)

