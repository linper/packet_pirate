#ifndef PKT_LST_H
#define PKT_LST_H

#include <stddef.h>
#include <string.h>
#include <sys/types.h>

/**
 * @brief Gets filtered packet. Intended to be used by end user.
 * @param pkt_list generic list of filtered packets
 * @param tag tag associated with packet/filter
 * @return packet struct if succeded, NULL otherwise
 */
struct packet *get_packet_by_tag(struct glist *pkt_list, const char *tag);

/**
 * @brief Gets filtered packet's entry. Intended to be used by end user.
 * @param pkt_list generic list of filtered packets
 * @param tag tag associated with packet's/filter's entry
 * @return packet entry struct if succeded, NULL otherwise
 */
struct p_entry *get_packet_entry_by_tag(struct glist *pkt_list,
										const char *tag);

/**
 * @brief Gets filtered packet's entry. Intended to be used by end user.
 * @param pkt_list generic list of filtered packets
 * @param pac packet structure to include in search
 * @param tag tag associated with packet's/filter's entry
 * @return packet entry struct if succeded, NULL otherwise
 */
struct p_entry *get_packet_entry_by_tag2(struct glist *pkt_list,
										 struct packet *pac, const char *tag);

#endif
