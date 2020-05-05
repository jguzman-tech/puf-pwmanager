#!/bin/bash

# This is really the enrollment step
if [ "$#" -eq 2 ]
then
    address="$1"
    new_value="$2"
    mysql --execute="UPDATE inf639.bank
SET value = '${new_value}', balance = 0
WHERE address = '${address}'"
else
    echo "illegal number of parameters, aborting..."
fi
