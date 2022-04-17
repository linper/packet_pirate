#!/bin/bash

resources="$(ls ${TST_DIR}/output_test/resources | grep '.pcap')"
target="test_program"
 
cp "${ROOT_DIR}/.config" "${ROOT_DIR}/.config.bkp"
cp "${TST_DIR}/output_test/test_config" "${ROOT_DIR}/.config"

make -C "${ROOT_DIR}" clean compile > /dev/null

[ $? -ne 0 ] && {
	echo "Failed to build project. Quiting..."
	mv "${ROOT_DIR}/.config.bkp" "${ROOT_DIR}/.config"
	exit 1
}

mv "${ROOT_DIR}/.config.bkp" "${ROOT_DIR}/.config"

for res in $resources; do
	filt="$(echo $res | cut -d'.' -f 1)"
	tp="$(echo $res | cut -d'.' -f 2)"
	cnt="$(echo $res | cut -d'.' -f 3)"

	[ -n "$filt" ] && [ -n "$tp" ] && [ -n "$cnt" ] || {
		echo "Test file: $res name is invalid, Skipping..."
		continue
	}

	echo -n "Filter:$filt Type:$tp Count:$cnt"

	result=$(${BIN_DIR}/${target} -s ${TST_DIR}/output_test/resources/${res} -v 1 | grep -A 8 -E "─${filt}:")
	[ -z "$result" ] && {
		echo "Filter: $filt not found, Skipping..."
		continue
	}

	ans=$(echo $result | grep -Eo "${tp}:.*" | cut -d' ' -f 2)
	[ -z "$ans" ] && {
		echo "Type: $tp not found, Skipping..."
		continue
	}

	if [ "$ans" -ne "$cnt"  ]; then
		echo " ERROR: expected ${cnt} got ${ans}"
		continue
	else
		echo " OK"
	fi
done

exit 0

