
//>>>FILTER_INCLUDES<<<

#include "../include/f_reg.h"


struct filter *filter_arr[] = {
//>>>FILTER_STRUCTS<<<
    NULL
};

void collect_filters(struct filter ***arr_ptr)
{
    *arr_ptr = filter_arr;
}

