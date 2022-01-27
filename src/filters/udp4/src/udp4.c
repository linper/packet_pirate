#include "../include/udp4.h"

static struct f_entry udp4_packet[] = {
/*  TAG 			ENTRY TYPE		LENG TH 	FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"udp4_sport", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_dport", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_len", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_cksum", 	ET_DATAFIELD, 	E_LEN(2), 	0, 		ERF_UINT_LE, 		EWF_UINT},
	{"udp4_pld", 	ET_DATAFIELD,	E_PAC_OFF_OF("udp4_sport", "udp4_len"),	EF_PLD,	ERF_BIN, 	EWF_NONE},
}; 

static void intercept(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	(void)args;
	(void)header;
	(void)packet;
	return;
}

static bool validate()
{
	return true;
}

struct filter udp4_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "udp4",
	.pre_filter = intercept,
	.post_filter = NULL,
	.validate = validate,
	.entries = udp4_packet,
	.n_entries = FILTER_LEN(udp4_packet),
};
	


