
#include "filters/ethernet/include/ethernet.h"
#include "filters/ipv4/include/ipv4.h"
#include "filters/tcp/include/tcp.h"


#include "../include/f_reg.h"

struct filter *filter_arr[] = {
	    &ethernet_filter,
    &ipv4_filter,
    &tcp_filter,

	NULL
};

