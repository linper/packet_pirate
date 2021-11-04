#ifndef PACKET_H
#define PACKET_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#include "utils.h"
#include "filter.h"
#include "ext_filter.h"
#include "ef_tree.h"
#include "converter.h"


/**
 * @brief Builds packet struct based on provided extended filter tree node and fills entries
 * with supplied data. 
 * @param p_ptr pointer to packet to be returned
 * @param node extended filter tree node to derive packet form
 * @param data captured packet data
 * @param len length of captured packet
 * @param read_off pointer pointed to current read position in 'data'
 * @return status wether packet ware split succesfully
 */
status_val derive_packet(struct packet **p_ptr, struct ef_tree *node, const u_char *data, size_t len, size_t *read_off);

/**
 * @brief Frees packet stuct and all its entries
 * @param p pointer to packet struct
 * @return Void
 */
void packet_free(struct packet *p);

#endif
