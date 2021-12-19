#!/bin/bash

export ROOT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/.." &> /dev/null && pwd )
export SRC_DIR=${ROOT_DIR}/src
export SCR_DIR=${ROOT_DIR}/scripts
export INC_DIR=${ROOT_DIR}/include
export TMP_DIR=${ROOT_DIR}/tmp  
export RES_DIR=${ROOT_DIR}/resources
export BLD_DIR=${ROOT_DIR}/build
export BIN_DIR=${BLD_DIR}/bin
export BLD_TMP_DIR=${BLD_DIR}/tmp
export FIL_DIR=${SRC_DIR}/filters

function usage () {
	echo "Usage : [-h] <connamd> <target> [params ...]
	Options:
	-h|--help       Display this message"
}

if [ $# -eq 0 ]; then
	usage
	exit 1
fi

while [ $# -gt 0 ]; do
	case $1 in
		-h|--help)
			usage
			exit 0
			;;
		delete)
			shift
			if [ $# -eq 0 ]; then
				echo "Not target given:"
				usage
				exit 1
			fi

			while [ $# -gt 0 ]; do
				case $1 in
					filter)
						shift
						${SCR_DIR}/delete_filter.sh "$@"
						exit $?
						;;
					*)
						echo "Unrecognised target: ${arg}
						Available targets: filter"
						usage
						exit 1
						;;
				esac
			done
			;;
		new)
			shift
			if [ $# -eq 0 ]; then
				echo "Not target given:"
				usage
				exit 1
			fi

			while [ $# -gt 0 ]; do
				case $1 in
					filter)
						shift
						${SCR_DIR}/generate_filter.sh "$@"
						exit $?
						;;
					*)
						echo "Unrecognised target: ${arg}
						Available targets: filter"
						usage
						exit 1
						;;
				esac
			done
			;;
		update)
			shift
			if [ $# -eq 0 ]; then
				echo "Not target given:"
				usage
				exit 1
			fi

			while [ $# -gt 0 ]; do
				case $1 in
					filter)
						shift
						${SCR_DIR}/regen_filter_links.sh
						exit $?
						;;
					*)
						echo "Unrecognised target: ${arg}
						Available targets: filter"
						usage
						exit 1
						;;
				esac
			done
			;;
		*)
			echo "Unrecognised command: ${arg}"
			usage
			exit 1
			;;
	esac
done


