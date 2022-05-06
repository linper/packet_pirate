#include <stdlib.h>

#include "../../../../include/utils.h"
#include "../../../../include/glist.h"
#include "../../../../include/ef_tree.h"
#include "../../../../include/ext_filter.h"
#include "../../../../include/filter.h"

static struct f_entry udp_packet[] = {
	/* TAG 			LENGTH 		MUL 	FLAGS 	READ FORMAT 	WRITE FORMAT */
	{ "udp_sport", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 	EWF_UINT },
	{ "udp_dport", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 	EWF_UINT },
	{ "udp_len", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 	EWF_UINT },
	{ "udp_cksum", 	E_LEN(2), 	8, 		0, 		ERF_UINT_BE, 	EWF_UINT },
	{ "udp_pld", 	E_PAC_OFF_OF("udp_sport", "udp_len"), 8, EF_PLD_REG, ERF_BIN, EWF_RAW },
};

static vld_status validate_udp(struct packet *p, struct ef_tree *node)
{
	(void)p;
	(void)node;

	struct p_entry *pe;
	/*struct packet *pp = get_packet_by_tag(p, "ipv4");*/
	struct packet *pp = p->prev;
	if (!pp) {
		return VLD_DROP;
	}

	if (!strcmp(pp->packet_tag, "ipv6")) {
		pe = PENTRY(pp, "ipv6_n_head");
		//udp protocol is indicated as 17 in ipv4 packet
		if (pe->conv_data.ulong != 17) {
			return VLD_DROP;
		}
	} else if (!strcmp(pp->packet_tag, "ipv4")) {
		pe = PENTRY(pp, "ipv4_proto");
		//udp protocol is indicated as 17 in ipv4 packet
		if (pe->conv_data.ulong != 17) {
			return VLD_DROP;
		}
	} else {
		return VLD_DROP;
	}

	return VLD_PASS;
}

static struct filter udp_filter = {
	.parent_tag = "ipv4",
	.packet_tag = "udp",
	.validate = validate_udp,
	.entries = udp_packet,
	.n_entries = FILTER_LEN(udp_packet),
};

INIT_FILTER(udp_filter)

