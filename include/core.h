/**
 * @file core.h
 * @brief Description of core "Packet Pirate's" interface. Only used by main.c
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef CORE_H
#define CORE_H

#include <pcap.h>

#include "utils.h"

/**
 * @brief Initializes whole filtering system
 * @return Status whether initialization succeded
 */
status_val core_init();

/**
 * @brief Filtering entrypoint whole capture by pcap 
 * @param[in] *args 	Arguments supplied to pcap's capture callback
 * @param[in] *header 	Timestamp, packet length and captured packet length
 * @param[out] *packet 	Captured packet data
 * @return Void
 */
void core_filter(u_char *args, const struct pcap_pkthdr *header,
				 const u_char *packet);

/**
 * @brief Frees whole filtering system
 * @return Status whether destruction succeded
 */
void core_destroy();

#endif
