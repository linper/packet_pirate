#!/bin/bash

filters="$(ls -d ${FIL_DIR}/*/ | rev | cut -d'/' -f 2 | rev)"

kcfg=""
mkfl=""

for flt in $filters; do
	FLT="$(echo ${flt} | tr '[:lower:]' '[:upper:]')"

	
	kcfg=${kcfg}"source \"src/filters/${flt}/KConfig\"\n"
	
	mkfl=${mkfl}"obj-\$(CONFIG_FILTER_${FLT}) += ${flt}/\n"
	mkfl=${mkfl}"inc-\$(CONFIG_FILTER_${FLT}) += ${flt}/\n"
done

echo -e "
${mkfl}
.PHONY all:

all:
	\$(MAKE) -f \$(SCR_DIR)/Makefile.build dir=\$(dir) obj=\$(obj) objs=\"\$(\$(obj)-y)\"
" > ${FIL_DIR}/Makefile

echo -e "
menu \"Filters\"

${kcfg}
endmenu
" > ${FIL_DIR}/KConfig

echo "Regenerated: ${FIL_DIR}/KConfig
Regenerated: ${FIL_DIR}/Makefile"
