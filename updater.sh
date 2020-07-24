#!/bin/bash

GEMNASIUM_DB_PATH=${GEMNASIUM_DB_PATH:-"/opt/gemnasium-db"}
cd "${GEMNASIUM_DB_PATH}"

while true; do
  changed=0
  git remote update && git status -uno | grep -q 'Your branch is behind' && changed=1
  if [ $changed = 1 ]; then
    git pull
    echo "Updated successfully";
  else
    echo "Up-to-date"
  fi
  sleep 1h

done

