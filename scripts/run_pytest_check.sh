#!/bin/bash

modules=( "common" "node" )

for i in "${modules[@]}"
do
    echo "indy_$i"
done

echo $GITHUB_WORKSPACE

# echo "::set-output name=matrix-common::$(python scripts/pytest_mark_check.py indy_common)"
# echo "::set-output name=matrix-node::$(python scripts/pytest_mark_check.py indy_node)"
