#!/bin/bash

modules=( "common" "node" )
errs=0

for m in "${modules[@]}"
do
    out=$(python3 scripts/pytest_mark_check.py indy_$m)

    echo "$out"
    
    result=$(echo $out | jq '.status')

    if [[ "$result" = "\"success\"" ]]; then
        echo "::set-output name=matrix-$m::$(echo $out | jq 'del(.status)' | jq 'del(.errs)')"
    else
        ((errs=errs+1))
        echo "$(echo $out | jq '.errors' | jq .[])"
    fi
done


if [[ errs -gt 0 ]]; then 
    exit 1
fi
