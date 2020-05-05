#!/bin/bash

if [ "$#" -eq 2 ]
then
    start="$1"
    end="$2"
    mysql --execute="SELECT * FROM inf639.pwmanager2
WHERE address >= '${start}' and address < '${end}'"
else
    echo "illegal number of parameters, aborting..."
fi
