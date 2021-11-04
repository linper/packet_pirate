#ifndef CORE_H
#define CORE_H

#include <pcap.h>

#include "utils.h"
#include "packet.h"
#include "filter.h"
#include "ext_filter.h"
#include "filter_hmap.h"
#include "ef_tree.h"
#include "f_reg.h"
#include "glist.h"

#define CAP_PKTS 256 //initial captured packets list capacity

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
void core_filter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
 * @brief Frees whole filtering system
 * @return status value wether destruction succeded
 */
void core_destroy();


#endif
