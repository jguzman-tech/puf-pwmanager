#!/bin/bash

if [ "$#" -eq 1 ]
then
    address="$1"
    output=$(mysql --execute="SELECT value FROM inf639.bank
WHERE address = '$address'")
    output=$(echo -n "${output}" | sed -n '2p' | grep -oE "[0-9a-f]+")
    echo "${output}"
else
    echo "illegal number of parameters, aborting..."
fi
