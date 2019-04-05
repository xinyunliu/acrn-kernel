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
		git diff -p 2e90d6307e2b..ec3e9ab7b624 $p
	fi;

done < changed.list

echo "Total: $COUNTER changed: $COUNTER2 added: $COUNTER3"

