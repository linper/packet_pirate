#include "../include/filter.h"


//compatability matrix between read and write formats
//lines - write
//columns - read
unsigned char rw_comp_mat[_EWF_COUNT][_ERF_COUNT] = {
    {0, 0, 0, 0},
    {0, 0, 0, 0},
    {0, 0, 0, 0},
    {0, 0, 0, 0},
    {0, 1, 1, 1},
    {0, 0, 0, 0},
};
