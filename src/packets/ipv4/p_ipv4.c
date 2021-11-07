#include "p_ipv4.h"


static struct f_entry ipv4_packet[] = {
/*  TAG 		ENTRY TYPE	LENGTH 				FLAGS 	READ FORMAT 	WRITE FORMAT */
    {"ipv4_vhl", 	ET_BITFIELD,	E_LEN(1), 			0, 	ERF_NONE, 	EWF_NONE},
    {"ipv4_ver", 	ET_FLAG,	E_BITS("ipv4_vhl", 0, 4), 	0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_ihl", 	ET_FLAG,	E_BITS("ipv4_vhl", 4, 4), 	0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_tos", 	ET_BITFIELD,	E_LEN(1), 			0, 	ERF_NONE, 	EWF_NONE},
    {"ipv4_dscp", 	ET_FLAG,	E_BITS("ipv4_tos", 0, 6), 	0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_ecn", 	ET_FLAG,	E_BITS("ipv4_tos", 6, 2), 	0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_len", 	ET_OFFSET,	E_LEN(2), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_id", 	ET_DATA,	E_LEN(2), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_fl_off", 	ET_BITFIELD,	E_LEN(2), 			0, 	ERF_NONE, 	EWF_NONE},
    {"ipv4_flags", 	ET_FLAG,	E_BITS("ipv4_fl_off", 0, 2), 	0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_frag_off", 	ET_FLAG,	E_BITS("ipv4_fl_off", 2, 14), 	0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_ttl", 	ET_DATA,	E_LEN(1), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_proto", 	ET_DATA,	E_LEN(1), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_cksum", 	ET_DATA,	E_LEN(2), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_src", 	ET_DATA,	E_LEN(4), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_dest", 	ET_DATA,	E_LEN(4), 			0, 	ERF_UINT_LE, 	EWF_UINT},
    {"ipv4_opt", 	ET_DATA,	E_PAC_OFF_OF("ipv4_ihl"),	EF_OPT,	ERF_UINT_LE, 	EWF_UINT},
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

struct filter ipv4_filter = {
    .parent_tag = "ethernet",
    .packet_tag = "ipv4",
    .pre_filter = intercept,
    .post_filter = NULL,
    .validate = validate,
    .entries = ipv4_packet,
    .n_entries = FILTER_LEN(ipv4_packet),
};
    


