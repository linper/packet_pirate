
//gen start
#include "packets/eth/p_eth.h"
#include "packets/ipv4/p_ipv4.h"
//gen end

#include "../include/packet_registry.h"


struct filter *filter_arr[] = {
//gen start
    &eth_filter,
    &ipv4_filter,
//gen end
    NULL
};

void collect_packets(struct filter ***arr_ptr)
{
    *arr_ptr = filter_arr;
}

