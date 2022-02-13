#include "../include/ethernet.h"

static struct f_entry ethernet_packet[] = {
/*  TAG 			LENGTH 		MUL	FLAGS 		READ FORMAT 	WRITE FORMAT */
	{"eth_dhost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},
	{"eth_shost", 	E_LEN(6), 	8,	0, 			ERF_STR, 		EWF_HEX_DT},
	{"eth_type", 	E_LEN(2), 	8,	0, 			ERF_UINT_LE, 	EWF_UINT},
	{"eth_pld", 	E_UNKN, 	8,	EF_PLD_REG, ERF_BIN,		EWF_RAW},
}; 

struct filter ethernet_filter = {
	.parent_tag = {0},
	.packet_tag = "ethernet",
	.entries = ethernet_packet,
	.n_entries = FILTER_LEN(ethernet_packet),
};
	


