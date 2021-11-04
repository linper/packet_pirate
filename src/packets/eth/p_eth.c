#include "p_eth.h"


static struct f_entry eth_packet[] = {
/*  TAG 	ENTRY TYPE	LENGTH 		FLAGS 	READ FORMAT 	WRITE FORMAT */
    {"dhost", 	ET_DATA, 	E_LEN(6), 	0, 	ERF_STR, 	EWF_HEX_STR},
    {"shost", 	ET_DATA,	E_LEN(6), 	0, 	ERF_STR, 	EWF_HEX_STR},
    {"type", 	ET_DATA,	E_LEN(2), 	0, 	ERF_UINT, 	EWF_HEX_STR},
    /*{"dhost", 	ET_DATA, 	E_LEN(6), 	0, 	ERF_STR, 	EWF_STR},*/
    /*{"shost", 	ET_DATA,	E_LEN(6), 	0, 	ERF_STR, 	EWF_STR},*/
    /*{"type", 	ET_DATA,	E_LEN(2), 	0, 	ERF_UINT, 	EWF_UINT},*/
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

struct filter eth_filter = {
    .parent_tag = {0},
    .packet_tag = "ethernet",
    .pre_filter = intercept,
    .post_filter = NULL,
    .validate = validate,
    .entries = eth_packet,
    .n_entries = FILTER_LEN(eth_packet),
};
    


