#!/bin/bash

resources="$(ls ./resources | grep ".pcap")"
target="test_program"

if [ -f ../../.config ]; then
	cp ../../.config ./.config.bkp
else 
	cp test_config ./.config.bkp
fi

cp test_config ../../.config

cwd="$(pwd)"
cd ../..
make clean compile > /dev/null

[ $? -ne 0 ] && {
	echo "Failed to buiild project. Quiting..."
	cp ./.config.bkp ../../.config
	exit 1
}

cd $cwd

for res in $resources; do
	filt="$(echo $res | cut -d'.' -f 1)"
	tp="$(echo $res | cut -d'.' -f 2)"
	cnt="$(echo $res | cut -d'.' -f 3)"

	[ -n "$filt" ] && [ -n "$tp" ] && [ -n "$cnt" ] || {
		echo "Test file: $res name is invalid, Skipping..."
		continue
	}

	echo -n "Filter:$filt Type:$tp Count:$cnt"

	result=$(../../build/bin/${target} -s ./resources/${res} -v 1 | grep -A 8 -E "─${filt}:")
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

cp ./.config.bkp ../../.config

exit 0

