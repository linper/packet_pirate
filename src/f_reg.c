
//gen start
#include "packets/eth/include/p_eth.h"
#include "packets/ipv4/include/p_ipv4.h"
//gen end

#include "../include/f_reg.h"


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

