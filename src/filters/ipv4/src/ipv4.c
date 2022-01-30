#include "../include/ipv4.h"

static struct f_entry ipv4_packet[] = {
/*  TAG 			ENTRY TYPE		LENGTH 						FLAGS 	READ FORMAT 	WRITE FORMAT */
	{"ipv4_vhl", 	ET_BITFIELD, 	E_LEN(1), 					0, 		ERF_BIN, 		EWF_NONE},
	{"ipv4_ver", 	ET_FLAG,		E_BITS("ipv4_vhl", 0, 4), 	0, 		ERF_UINT_LE, 	EWF_UINT},
	{"ipv4_ihl", 	ET_FLAG,		E_BITS("ipv4_vhl", 4, 4), 	EF_32BITW, 	ERF_UINT_LE, 	EWF_UINT},
	{"ipv4_tos", 	ET_BITFIELD, 	E_LEN(1), 					0, 		ERF_BIN, 		EWF_NONE},
	{"ipv4_dscp", 	ET_FLAG,		E_BITS("ipv4_tos", 0, 6), 	0, 		ERF_UINT_LE, 	EWF_HEX_STR},
	{"ipv4_ecn", 	ET_FLAG,		E_BITS("ipv4_tos", 6, 2), 	0, 		ERF_UINT_LE, 	EWF_HEX_STR},
	{"ipv4_len", 	ET_DATAFIELD,	E_LEN(2), 					0, 		ERF_UINT_LE, 	EWF_UINT},
	{"ipv4_id", 	ET_DATAFIELD,	E_LEN(2), 					0, 		ERF_UINT_LE, 	EWF_UINT},
	/*{"ipv4_fl_off", ET_BITFIELD, 	E_LEN(2), 					0, 		ERF_BIN, 		EWF_RAW},*/
	{"ipv4_fl_off", ET_BITFIELD, 	E_LEN(2), 					0, 		ERF_BIN, 		EWF_NONE},
	{"ipv4_flags", 	ET_FLAG,		E_BITS("ipv4_fl_off", 0, 2),0, 		ERF_UINT_LE, 	EWF_HEX_STR},
	{"ipv4_frag_off",	ET_FLAG, 	E_BITS("ipv4_fl_off", 2, 14),	0, 	ERF_UINT_LE, 	EWF_HEX_STR},
	{"ipv4_ttl", 	ET_DATAFIELD,	E_LEN(1), 					0, 		ERF_UINT_LE, 	EWF_UINT},
	{"ipv4_proto", 	ET_DATAFIELD,	E_LEN(1), 					0, 		ERF_UINT_LE, 	EWF_UINT},
	{"ipv4_cksum", 	ET_DATAFIELD,	E_LEN(2), 					0, 		ERF_UINT_LE, 	EWF_UINT},
	{"ipv4_src", 	ET_DATAFIELD,	E_LEN(4), 					0, 		ERF_BIN, 		EWF_RAW},
	/*{"ipv4_src", 	ET_DATAFIELD,	E_LEN(4), 					0, 		ERF_UINT_LE, 	EWF_HEX_STR},*/
	{"ipv4_dest", 	ET_DATAFIELD,	E_LEN(4), 					0, 		ERF_UINT_LE, 	EWF_HEX_STR},
	{"ipv4_opt", 	ET_DATAFIELD,	E_PAC_OFF_OF("ipv4_vhl", "ipv4_ihl"),	EF_OPT,	ERF_UINT_LE,EWF_HEX_STR},
	{"ipv4_pld", 	ET_DATAFIELD,	E_PAC_OFF_OF("ipv4_vhl", "ipv4_len"),	EF_PLD,	ERF_BIN, 	EWF_NONE},
}; 

static vld_status validate_ipv4(struct packet *p, struct ef_tree *node)
{
	struct p_entry *pe;

	//vhl is always equal to 4
	pe = PENTRY(node, p, "ipv4_ver");
	if (pe->conv_data.ulong != 4) {
		return VLD_DROP;
	}

	//ihl is always [5; 15]
	pe = PENTRY(node, p, "ipv4_ihl");
	if (pe->conv_data.ulong < 5) {
		return VLD_DROP;
	} else if (pe->conv_data.ulong > 5) {
		pe = PENTRY(node, p, "ipv4_opt");
		//if ihl is greater than 5, options must exist
		if (!pe->raw_len) {
			return VLD_DROP;
		}
	}

	//total length is always [20; 65535]
	pe = PENTRY(node, p, "ipv4_len");
	if (pe->conv_data.ulong < 20) {
		return VLD_DROP;
	}

	//MSB (evil bit) is always 0
	pe = PENTRY(node, p, "ipv4_flags");
	if (pe->conv_data.ulong & 0x4) {
		return VLD_DROP;
	}

	return VLD_PASS;
}

struct filter ipv4_filter = {
	.parent_tag = "ethernet",
	.packet_tag = "ipv4",
	.validate = validate_ipv4,
	.entries = ipv4_packet,
	.n_entries = FILTER_LEN(ipv4_packet),
};
	


