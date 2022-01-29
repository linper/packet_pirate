#include "../include/>>>FILTER_DB<<<.h"

static struct f_entry >>>FILTER_DB<<<_packet[] = {
	/*ethernet packet example*/
/*  TAG 			ENTRY TYPE	LENG TH 	FLAGS 	READ FORMAT 	WRITE FORMAT */
	/*{"dhost", 	ET_DATAFIELD, 	E_LEN(6), 	0, 		ERF_STR, 		EWF_HEX_STR},*/
	/*{"shost", 	ET_DATAFIELD,	E_LEN(6), 	0, 		ERF_STR, 		EWF_HEX_STR},*/
	/*{"type", 		ET_DATAFIELD,	E_LEN(2), 	0, 		ERF_UINT_LE, 	EWF_HEX_STR},*/
	/*{"dhost", 	ET_DATAFIELD, 	E_LEN(6), 	0, 		ERF_STR, 		EWF_STR},*/
	/*{"shost", 	ET_DATAFIELD,	E_LEN(6), 	0, 		ERF_STR, 		EWF_STR},*/
	/*{"type", 		ET_DATAFIELD,	E_LEN(2), 	0, 		ERF_UINT_LE, 	EWF_UINT},*/
}; 

static void intercept(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	(void)args;
	(void)header;
	(void)packet;
	return;
}

static vld_status validate()
{
	return VLD_PASS;
}

struct filter >>>FILTER_DB<<<_filter = {
	.parent_tag = >>>PARENT_BUF_DB<<<,
	.packet_tag = ">>>FILTER_DB<<<",
	.pre_filter = intercept,
	.post_filter = NULL,
	.validate = validate,
	.entries = >>>FILTER_DB<<<_packet,
	.n_entries = FILTER_LEN(>>>FILTER_DB<<<_packet),
};
	


