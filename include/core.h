#ifndef CORE_H
#define CORE_H

#include <pcap.h>

#include "filter.h"
#include "ext_filter.h"
#include "filter_hmap.h"
#include "ef_tree.h"
#include "packet_registry.h"


status_val core_init();

status_val core_filter(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);




#endif
