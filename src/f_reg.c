
//gen start
#include "filters/eth/include/eth.h"
#include "filters/eth/include/ipv4.h"

//gen end

#include "../include/f_reg.h"


struct filter *filter_arr[] = {
//gen start
    &eth_filter,
    &ipv4_filter,

//gen end
    NULL
};

void collect_filters(struct filter ***arr_ptr)
{
    *arr_ptr = filter_arr;
}

