/**
 * @file packet.h
 * @brief Description of packet parsing interface
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include "utils.h"
#include "filter.h"

/**
 * @brief Builds packet struct based on provided extended filter tree node and fills entries
 * with supplied data. 
 * @param[in] *pkt_list 		Generic list that contains already parsed packets from `data``
 * @param[in] *node 			Extended filter tree node to derive packet form
 * @param[in] *data 			Captured packet data
 * @param[in] *header 			Capture header/metadata
 * @param[in, out] *read_off 	Pointer to current read position in `data`
 * @param[out] **p 				Double pointer to return packet
 * @return Status whether packet were split succesfully
 */
status_val derive_packet(struct glist *pkt_list, struct ef_tree *node,
						 const u_char *data, const struct pcap_pkthdr *header,
						 unsigned *read_off, struct packet **p);

/**
 * @brief Frees packet stuct and all its entries
 * @param[in] *p Pointer to packet struct
 * @return Void
 */
void packet_free(struct packet *p);

#endif
