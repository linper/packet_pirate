#include "../include/udp4.h"

static struct f_entry udp4_packet[] = {
/*  TAG 			LENGTH 		MUL 	FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"udp4_sport", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 		EWF_UINT},
	{"udp4_dport", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 		EWF_UINT},
	{"udp4_len", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 		EWF_UINT},
	{"udp4_cksum", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 		EWF_UINT},
	{"udp4_pld", 	E_PAC_OFF_OF("udp4_sport", "udp4_len"), 8, EF_PLD_REG, ERF_BIN, EWF_RAW},
}; 

static vld_status validate_udp4(struct packet *p, struct ef_tree *node)
{
	(void)p;
	(void)node;
	
	struct p_entry *pe;
	struct packet *pp = get_packet_by_tag(p, "ipv4");
	if (!pp) {
		return VLD_DROP;
	}
	
	//udp protocol is indicated as 17 in ipv4 packet
	pe = PENTRY(pp, "ipv4_proto");
	if (pe->conv_data.ulong != 17) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

struct filter udp4_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "udp4",
	.validate = validate_udp4,
	.entries = udp4_packet,
	.n_entries = FILTER_LEN(udp4_packet),
};
	
INIT_FILTER(udp4_filter)

