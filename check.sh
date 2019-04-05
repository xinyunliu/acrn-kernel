#!/bin/bash
COUNTER=0
COUNTER2=0
COUNTER3=0
src_dir=/home/woliu/Work/eb_rebase/acrn-kernel
flag_copy=1
while read p; do
	let COUNTER=COUNTER+1
	if [ -f $p ]; then
		let COUNTER2=COUNTER2+1
		echo "$p";
	elif [ $flag_copy = 1 ]; then
		if [ -f $src_dir/$p ]; then
			let COUNTER3=COUNTER3+1
			echo "cp $src_dir/$p $p"
			mkdir -p $(dirname ${p})
			cp $src_dir/$p $p
		fi
	fi;

done < change_files

echo "Total: $COUNTER changed: $COUNTER2 added: $COUNTER3"

