#include <stdlib.h>

#include "../../../../include/utils.h"
#include "../../../../include/glist.h"
#include "../../../../include/ef_tree.h"
#include "../../../../include/ext_filter.h"
#include "../../../../include/filter.h"

static struct f_entry tcp_packet[] = {
/*  TAG 			LENGTH 			MUL		FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"tcp_sport", 	E_LEN(2), 		8,		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_dport", 	E_LEN(2), 		8,		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_seq", 	E_LEN(4), 		8,		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_ackn", 	E_LEN(4), 		8,		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_dt_off", 	E_LEN(4), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_flg", 	E_LEN(12), 		1,		EF_DUB, 	ERF_BIN, 		EWF_HEX_STR},
	{"tcp_rez", 	E_LEN(3), 		1, 		EF_NOWRT, 	ERF_UINT_BE, 	EWF_UINT},
	{"tcp_ns", 		E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_cwr", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_ece", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_urg", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_ack", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_psh", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_rst", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_syn", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_fin", 	E_LEN(1), 		1, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_win", 	E_LEN(2), 		8, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_cksum", 	E_LEN(2), 		8, 		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_urgp", 	E_LEN(2), 		8,		0, 			ERF_UINT_BE, 	EWF_UINT},
	{"tcp_opt", 	E_PAC_OFF_OF("tcp_sport", "tcp_dt_off"), 32, EF_OPT, ERF_BIN, EWF_HEXDUMP},
	{"tcp_pld", 	E_PAC_OFF_OF("ipv4_ver", "ipv4_len"), 8, EF_PLD_REG, ERF_BIN, EWF_RAW},
}; 

static vld_status validate_tcp(struct packet *p, struct ef_tree *node)
{
	struct p_entry *pe;
	(void)node;

	struct packet *pp = get_packet_by_tag(p, "ipv4");
	if (!pp) {
		return VLD_DROP;
	}
	
	//udp protocol is indicated as 6 in ipv4 packet
	pe = PENTRY(pp, "ipv4_proto");
	if (pe->conv_data.ulong != 6) {
		return VLD_DROP;
	}

	//data offset is always [5; 15]
	pe = PENTRY(p, "tcp_dt_off");
	if (pe->conv_data.ulong < 5) {
		return VLD_DROP;
	}

	//rezerved bits should be 0
	pe = PENTRY(p, "tcp_rez");
	if (pe->conv_data.ulong) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

static struct filter tcp_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "tcp",
	.validate = validate_tcp,
	.entries = tcp_packet,
	.n_entries = FILTER_LEN(tcp_packet),
};
	
INIT_FILTER(tcp_filter)

