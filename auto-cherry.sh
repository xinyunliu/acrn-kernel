#!/bin/bash

set -e 

do_cherry_pick()
{

	COUNTER=0
	echo '' > commits_list.csv
	while IFS=" " read -r value1 value2 
	do
		printf -v j "%04d" ${COUNTER}
		echo "${j}: cherry-pick ${value1} - ${value2} ..."
		git cherry-pick ${value1}
		echo " Done:            ${value1}"
		let COUNTER=COUNTER+1
	done < "cherry-list.1"
}

do_generate_list()
{
	COUNTER=0
	echo '' > commits_list.csv
	while IFS=" " read -r value1 value2 
	do
		echo "${COUNTER}, ${value1}, ${value2}" >> commits_list.csv
		let COUNTER=COUNTER+1
	done < "cherry-list"
}


#do_generate_list
do_cherry_pick
