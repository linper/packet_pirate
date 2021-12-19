
#include "filters/ethernet/include/ethernet.h"
#include "filters/ipv4/include/ipv4.h"
#include "filters/udp/include/udp.h"


#include "../include/f_reg.h"

struct filter *filter_arr[] = {
	    &ethernet_filter,
    &ipv4_filter,
    &udp_filter,

	NULL
};

void collect_filters(struct filter ***arr_ptr)
{
	*arr_ptr = filter_arr;
}

