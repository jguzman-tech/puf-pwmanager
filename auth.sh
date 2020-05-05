#!/bin/bash

if [ "$#" -eq 2 ]
then
    address="$1"
    value="$2"
    output=$(mysql --execute="SELECT IF (value = '${value}', 'true', 'false')
FROM inf639.pwmanager2
WHERE address = '${address}'")
    output=$(echo -n "${output}" | sed -n '2p' | grep -oE "(true)|(false)")
    echo "${output}"
else
    echo "illegal number of parameters, aborting..."
fi
