#include "../include/>>>FILTER_NAME<<<.h"


static struct f_entry >>>FILTER_NAME<<<_packet[] = {
	/*ethernet packet example*/
/*  TAG 	ENTRY TYPE	LENG TH 		FLAGS 	READ FORMAT 	WRITE FORMAT */
    /*{"dhost", 	ET_DATA, 	E_LEN(6), 	0, 	ERF_STR, 	EWF_HEX_STR},*/
    /*{"shost", 	ET_DATA,	E_LEN(6), 	0, 	ERF_STR, 	EWF_HEX_STR},*/
    /*{"type", 	ET_DATA,	E_LEN(2), 	0, 	ERF_UINT_LE, 	EWF_HEX_STR},*/
    /*{"dhost", 	ET_DATA, 	E_LEN(6), 	0, 	ERF_STR, 	EWF_STR},*/
    /*{"shost", 	ET_DATA,	E_LEN(6), 	0, 	ERF_STR, 	EWF_STR},*/
    /*{"type", 	ET_DATA,	E_LEN(2), 	0, 	ERF_UINT_LE, 	EWF_UINT},*/
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

struct filter >>>FILTER_NAME<<<_filter = {
    .parent_tag = >>>PARENT_BUF_NAME<<<,
    .packet_tag = ">>>FILTER_NAME<<<",
    .pre_filter = intercept,
    .post_filter = NULL,
    .validate = validate,
    .entries = >>>FILTER_NAME<<<_packet,
    .n_entries = FILTER_LEN(>>>FILTER_NAME<<<_packet),
};
    


