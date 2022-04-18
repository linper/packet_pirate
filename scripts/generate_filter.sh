#!/bin/bash

function usage() {
	echo "Usage: <-n name> [options ...] 
Options:
    -n|--name       Provide name for filter
    -p|--parent     Provide name for parent filter
    -h|--help       Display this message"
}

function gen_filter() {
	cp -r ${RES_DIR}/filter/filter ${TMP_DIR}/${f_name_l} 
	mv ${TMP_DIR}/${f_name_l}/src/filter.c ${TMP_DIR}/${f_name_l}/src/${f_name_l}.c

	find ${TMP_DIR}/${f_name_l} -type f -not -path '*/\.*' -exec sed -i "s/>>>FILTER_UNAME<<</${f_name_u}/g" {} +
	find ${TMP_DIR}/${f_name_l} -type f -not -path '*/\.*' -exec sed -i "s/>>>FILTER_NAME<<</${f_name_l}/g" {} +

	if [ $f_parent_u ];then
		find ${TMP_DIR}/${f_name_l} -type f -not -path '*/\.*' -exec sed -i "s/>>>PARENT_BUF_NAME<<</\"${f_parent_l}\"/g" {} +
		find ${TMP_DIR}/${f_name_l} -type f -not -path '*/\.*' -exec sed -i "s/>>>SELECT_PARENT<<</select FILTER_${f_parent_u}/g" {} +
	else
		find ${TMP_DIR}/${f_name_l} -type f -not -path '*/\.*' -exec sed -i "s/>>>PARENT_BUF_NAME<<</{0}/g" {} +
		find ${TMP_DIR}/${f_name_l} -type f -not -path '*/\.*' -exec sed -i "s/>>>SELECT_PARENT<<<//g" {} +
	fi

	mv ${TMP_DIR}/${f_name_l} ${FIL_DIR}/${f_name_l}
}

f_name_u=
f_name_l=
f_parent_u=
f_parent_l=

if [ $# -eq 0 ]; then
	usage
	exit 1
fi

while [ $# -gt 0 ]; do
	case $1 in
		-n|--name)
			shift
			f_name_l="$(echo $1 | tr '[:upper:]' '[:lower:]')"
			f_name_u="$(echo $1 | tr '[:lower:]' '[:upper:]')"
			shift
			;;
		-p|--parent)
			shift
			f_parent_l="$(echo $1 | tr '[:upper:]' '[:lower:]')"
			f_parent_u="$(echo $1 | tr '[:lower:]' '[:upper:]')"
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unrecognised argument: ${arg}"
			usage
			exit 1
			;;
	esac
done

if [ -z "$f_name_l" ];then
	echo "Missing filter name"
	usage
	exit 1
fi

if [[ "${f_name_l}" =~ [^a-zA-Z0-9_] ]];then
	echo "Bad name format"
	usage
	exit 1
fi

if [ -z "{f_parent_l}" ] || [[ "${f_parent_l}" =~ [^a-zA-Z0-9_] ]];then
	echo "Bad parent name format"
	usage
	exit 1
fi

if [ -d "${FIL_DIR}/${f_name_l}" ]; then
	echo "Filter already exist, quiting..."
	exit 1
fi

ideps="$(grep -r "select FILTER_${FLT}" ${FIL_DIR}/*/KConfig | rev | cut -d'/' -f 2 | rev)"

if [ -z "$(ls -d ${FIL_DIR}/*/ | grep "/${f_parent_l}/")" ];then
	echo "Parent (${f_parent_l}) does not exist"
	echo "Are you realy want to create (${f_name_l}) filter (y/n)"

	read ans
	if [ "$ans" != "y" ];then
		echo "Filter (${f_name_l}) not created"
		exit 0
	fi
fi

gen_filter

echo "Generated filter (${f_name_l}) at: ${FIL_DIR}/${f_name_l}"

${SCR_DIR}/regen_filter_links.sh

exit 0
