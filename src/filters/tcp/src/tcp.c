#include "../include/tcp.h"

static struct f_entry tcp_packet[] = {
/*  TAG 			ENTRY TYPE		LENGTH 					FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"tcp_sport", 	ET_DATAFIELD, 	E_LEN(2), 				0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_dport", 	ET_DATAFIELD, 	E_LEN(2), 				0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_seq", 	ET_DATAFIELD, 	E_LEN(4), 				0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_ackn", 	ET_DATAFIELD, 	E_LEN(4), 				0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_flg", 	ET_BITFIELD, 	E_LEN(2), 				0, 		ERF_BIN, 		EWF_NONE},
	{"tcp_dt_off", 	ET_FLAG,		E_BITS("tcp_flg", 0, 4),EF_32BITW, ERF_UINT_LE, EWF_UINT},
	{"tcp_rez", 	ET_FLAG,		E_BITS("tcp_flg", 4, 3),0, 		ERF_UINT_LE, 	EWF_NONE},
	{"tcp_ns", 		ET_FLAG,		E_BITS("tcp_flg", 7, 1),0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_cwr", 	ET_FLAG,		E_BITS("tcp_flg", 8, 1),0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_ece", 	ET_FLAG,		E_BITS("tcp_flg", 9, 1),0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_urg", 	ET_FLAG,		E_BITS("tcp_flg", 10, 1),0, 	ERF_UINT_LE, 	EWF_UINT},
	{"tcp_ack", 	ET_FLAG,		E_BITS("tcp_flg", 11, 1),0, 	ERF_UINT_LE, 	EWF_UINT},
	{"tcp_psh", 	ET_FLAG,		E_BITS("tcp_flg", 12, 1),0, 	ERF_UINT_LE, 	EWF_UINT},
	{"tcp_rst", 	ET_FLAG,		E_BITS("tcp_flg", 13, 1),0, 	ERF_UINT_LE, 	EWF_UINT},
	{"tcp_syn", 	ET_FLAG,		E_BITS("tcp_flg", 14, 1),0, 	ERF_UINT_LE, 	EWF_UINT},
	{"tcp_fin", 	ET_FLAG,		E_BITS("tcp_flg", 15, 1),0, 	ERF_UINT_LE, 	EWF_UINT},
	{"tcp_cksum", 	ET_DATAFIELD, 	E_LEN(2), 				0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_urgp", 	ET_DATAFIELD, 	E_LEN(2), 				0, 		ERF_UINT_LE, 	EWF_UINT},
	{"tcp_opt", 	ET_DATAFIELD,	E_PAC_OFF_OF("tcp_sport", "tcp_dt_off"),EF_OPT,	ERF_UINT_LE, EWF_HEX_STR},
	{"tcp_pld", 	ET_DATAFIELD,	E_PAC_OFF_OF("ipv4_vhl", "ipv4_len"),	EF_PLD,	ERF_BIN, 	EWF_NONE},
}; 

static vld_status validate_tcp(struct packet *p, struct ef_tree *node)
{
	struct p_entry *pe;
	struct ef_tree *pn = node->par;

	struct packet *pp = get_packet_by_tag(pc.single_cap_pkt, "ipv4");
	if (!pp) {
		return VLD_DROP;
	}
	
	//udp protocol is indicated as 6 in ipv4 packet
	pe = PENTRY(pn, pp, "ipv4_proto");
	if (pe->conv_data.ulong != 6) {
		return VLD_DROP;
	}

	//data offset is always [5; 15]
	pe = PENTRY(node, p, "tcp_dt_off");
	if (pe->conv_data.ulong < 5) {
		return VLD_DROP;
	}

	//rezerved bits should be 0
	pe = PENTRY(node, p, "tcp_rez");
	if (pe->conv_data.ulong) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

struct filter tcp_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "tcp",
	.validate = validate_tcp,
	.entries = tcp_packet,
	.n_entries = FILTER_LEN(tcp_packet),
};
	

