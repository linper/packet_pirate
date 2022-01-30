#include "../include/udp4.h"

static struct f_entry udp4_packet[] = {
/*  TAG 			ENTRY TYPE		LENG TH 	FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"udp4_sport", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_dport", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_len", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_cksum", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_pld", 	ET_DATAFIELD,	E_PAC_OFF_OF("udp4_sport", "udp4_len"),	EF_PLD,	ERF_BIN, 	EWF_NONE},
}; 

static vld_status validate_udp4(struct packet *p, struct ef_tree *node)
{
	(void)p;
	
	struct p_entry *pe;
	struct ef_tree *pn = node->par;

	struct packet *pp = get_packet_by_tag(pc.single_cap_pkt, "ipv4");
	if (!pp) {
		return VLD_DROP;
	}
	
	//udp protocol is indicated as 17 in ipv4 packet
	pe = PENTRY(pn, pp, "ipv4_proto");
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
	


