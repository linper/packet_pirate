#ifndef CORE_H
#define CORE_H

#include <pcap.h>

#include "utils.h"

/**
 * @brief Initializes whole filtering system
 * @return status value wether initialization succeded
 */
status_val core_init();

/**
 * @brief Filtering entrypoint for every packet captured by pcap 
 * @param args some arguments
 * @param header timestamp, packet length and captured packet length
 * @param packet captured packet data
 * @return Void
 */
void core_filter(u_char *args, const struct pcap_pkthdr *header,
				 const u_char *packet);

/**
 * @brief Frees whole filtering system
 * @return status value wether destruction succeded
 */
void core_destroy();

#endif
