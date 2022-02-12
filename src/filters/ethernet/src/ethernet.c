#include "../include/ethernet.h"

static struct f_entry ethernet_packet[] = {
/*  TAG 			ENTRY TYPE		LENGTH 		FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"eth_dhost", 	ET_DATAFIELD, 	E_LEN(6), 	0, 			ERF_STR, 		EWF_HEX_DT},
	{"eth_shost", 	ET_DATAFIELD,	E_LEN(6), 	0, 			ERF_STR, 		EWF_HEX_DT},
	{"eth_type", 	ET_DATAFIELD,	E_LEN(2), 	0, 			ERF_UINT_LE, 	EWF_UINT},
	{"eth_pld", 	ET_DATAFIELD,	E_UNKN, 	EF_PLD | EF_NOWRT, ERF_BIN,	EWF_RAW},
}; 

struct filter ethernet_filter = {
	.parent_tag = {0},
	.packet_tag = "ethernet",
	.entries = ethernet_packet,
	.n_entries = FILTER_LEN(ethernet_packet),
};
	


