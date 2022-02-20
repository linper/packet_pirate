/**
 * @file pkt_list.h
 * @brief Description of the interface to get packets from generic list
 * @author Linas Perkauskas
 * @date 2022-02-20
 */

#ifndef PKT_LST_H
#define PKT_LST_H

#include <stddef.h>
#include <string.h>
#include <sys/types.h>

/**
 * @brief Gets filtered packet. Intended to be used by end user.
 * @param[in] *pkt_list Generic list of filtered packets
 * @param[in] *tag 		Tag associated with packet/filter
 * @return Packet struct if succeded, NULL otherwise
 */
struct packet *get_packet_by_tag(struct glist *pkt_list, const char *tag);

/**
 * @brief Gets filtered packet's entry. Intended to be used by end user.
 * @param[in] *pkt_list 	Generic list of filtered packets
 * @param[in] *pac 			Packet structure to include in search
 * @param[in] *tag 			Tag associated with packet's/filter's entry
 * @return Packet entry struct if succeded, NULL otherwise
 */
struct p_entry *get_packet_entry_by_tag2(struct glist *pkt_list,
										 struct packet *pac, const char *tag);

/**
 * @brief Gets filtered packet's entry. Intended to be used by end user.
 * @param[in] *pkt_list 	Generic list of filtered packets
 * @param[in] *tag 			Tag associated with packet's/filter's entry
 * @return Packet entry struct if succeded, NULL otherwise
 */
inline struct p_entry *get_packet_entry_by_tag(struct glist *pkt_list,
										const char *tag)
{
	return get_packet_entry_by_tag2(pkt_list, NULL, tag);
}

#endif
