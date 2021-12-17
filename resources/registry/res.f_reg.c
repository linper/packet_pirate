
//gen start
//>>>FILTER_INCLUDES<<<
//gen end

#include "../include/f_reg.h"


struct filter *filter_arr[] = {
//gen start
//>>>FILTER_STRUCTS<<<
//gen end
    NULL
};

void collect_filters(struct filter ***arr_ptr)
{
    *arr_ptr = filter_arr;
}

