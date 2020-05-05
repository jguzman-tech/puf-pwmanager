#!/bin/bash

if [ "$#" -eq 2 ]
then
    address="$1"
    added_funds="$2"
    mysql --execute="UPDATE inf639.bank
SET balance = balance + ${added_funds}
WHERE address = '${address}'"
else
    echo "illegal number of parameters, aborting..."
fi
