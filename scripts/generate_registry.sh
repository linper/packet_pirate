#!/bin/bash

reg_file="f_reg.c"

cp ${RES_DIR}/registry/res.${reg_file} ${TMP_DIR}/${reg_file} 

inc_sub=
struct_sub=

filters=$(grep -E "CONFIG_FILTER_.*=.*" ${ROOT_DIR}/.config | cut -d'=' -f 1 | cut -d'_' -f 3-  | tr '[:upper:]' '[:lower:]')

for flt in $filters; do
	inc_sub=${inc_sub}"#include \\\"filters\/eth\/include\/${flt}.h\\\"\\n"
	#struct_sub=${struct_sub}"\\n&${flt},"
	struct_sub=${struct_sub}"    \\&${flt}_filter,\\n"
done

sed -i "s/\/\/>>>FILTER_INCLUDES<<</${inc_sub}/g" ${TMP_DIR}/${reg_file}
sed -i "s/\/\/>>>FILTER_STRUCTS<<</${struct_sub}/g" ${TMP_DIR}/${reg_file}

cp ${TMP_DIR}/${reg_file} ${SRC_DIR}/${reg_file}

 
