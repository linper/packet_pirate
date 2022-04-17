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
 * @brief Builds packet struct and fills entries with supplied data. 
 * @param[in, out] *p 			Pointer to packet to derive
 * @param[in] *data 			Captured packet data
 * @param[in] *header 			Capture header/metadata
 * @param[in, out] *read_off 	Pointer to current read position in `data`
 * @return Status whether packet were split succesfully
 */
status_val derive_packet(struct packet *p, const u_char *data,
						 const struct pcap_pkthdr *header, unsigned *read_off);

/**
 * @brief Builds base packet struct based on provided extended filter and parent packet
 * @param[out] **p 				Double pointer to return packet
 * @param[in] *ef 				Pointer to esociated extended filter
 * @param[in] *last 			Pointer to parent packet
 * @return Status whether base packet created succesfully, or NULL otherwise
 */
status_val prepare_packet(struct packet **p, struct ext_filter *ef,
						  struct packet *last);

#endif
