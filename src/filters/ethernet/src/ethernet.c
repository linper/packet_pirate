#include "../include/ethernet.h"


static struct f_entry ethernet_packet[] = {
/*  TAG 		ENTRY TYPE	LENGTH 		FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"dhost", 	ET_DATAFIELD, 	E_LEN(6), 	0, 	ERF_STR, 		EWF_HEX_STR},
	{"shost", 	ET_DATAFIELD,	E_LEN(6), 	0, 	ERF_STR, 		EWF_HEX_STR},
	{"type", 	ET_DATAFIELD,	E_LEN(2), 	0, 	ERF_UINT_LE, 	EWF_HEX_STR},
	/*{"dhost",	ET_DATAFIELD, 	E_LEN(6), 	0, 	ERF_STR, 		EWF_STR},*/
	/*{"shost",	ET_DATAFIELD,	E_LEN(6), 	0, 	ERF_STR, 		EWF_STR},*/
	/*{"type", 	ET_DATAFIELD,	E_LEN(2), 	0, 	ERF_UINT_LE, 	EWF_UINT},*/
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

struct filter ethernet_filter = {
	.parent_tag = {0},
	.packet_tag = "ethernet",
	.pre_filter = intercept,
	.post_filter = NULL,
	.validate = validate,
	.entries = ethernet_packet,
	.n_entries = FILTER_LEN(ethernet_packet),
};
	


