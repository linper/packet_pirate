/**
 * @file pkt_list.c
 * @brief Implementation of the interface to get packets from generic list
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#include <string.h>

#include "../include/glist.h"
#include "../include/filter.h"
#include "../include/packet.h"
#include "../include/pkt_list.h"

struct p_entry *get_packet_entry_by_tag2(struct glist *pkt_list,
										 struct packet *pac, const char *tag)
{
	struct packet *p;

	p = pac;
	if (pac) {
		for (unsigned i = 0; i < p->e_len; i++) {
			if (!strcmp(p->entries[i].tag, tag)) {
				return &p->entries[i];
			}
		}
	}

	//searching in already parsed packets
	glist_foreach (void *e, pkt_list) {
		p = (struct packet *)e;
		for (unsigned i = 0; i < p->e_len; i++) {
			if (!strcmp(p->entries[i].tag, tag)) {
				return &p->entries[i];
			}
		}
	}

	return NULL;
}

struct packet *get_packet_by_tag(struct glist *pkt_list, const char *tag)
{
	struct packet *p;

	//searching in already parsed packets
	glist_foreach (void *e, pkt_list) {
		p = (struct packet *)e;
		if (!strcmp(p->packet_tag, tag)) {
			return p;
		}
	}

	return NULL;
}

