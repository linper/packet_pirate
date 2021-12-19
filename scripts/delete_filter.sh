#!/bin/bash

function usage() {
	echo "Usage : [-h] <-n name>
	Options:
	-n|--name       Provide name of filter to delete"
}

function del_filter() {
	FLT="$(echo ${flt} | tr '[:lower:]' '[:upper:]')"
	ideps="$(grep -r "select FILTER_${FLT}" ${FIL_DIR}/*/KConfig | rev | cut -d'/' -f 2 | rev)"

	if [ "${ideps}" ];then
		echo "These filters depends on ${flt}: ${ideps}"
	fi

	echo "Are you realy want to delete ${flt} (y/n)"

	read ans

	if [ "$ans" = "y" ];then
		rm -r ${FIL_DIR}/${flt}
		echo "Deleted filter (${flt})"

		${SCR_DIR}/regen_filter_links.sh
	fi
}

flt=

if [ $# -eq 0 ]; then
	usage
	exit 1
fi

while [ $# -gt 0 ]; do
	case $1 in
		-n|--name)
			shift
			flt="$1"
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

if [ -z "${flt}" ];then
	echo "Missing filter name"
	usage
fi

if [ ! -d "${FIL_DIR}/${flt}" ]; then
	echo "No such filter, quiting..."
	exit 1
fi

del_filter

exit 0
