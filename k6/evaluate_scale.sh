#!/bin/bash
for i in {1..10}
do
  vus=$((i))
  echo "VUs == ${vus}"
  k6 run script.js --vus ${vus} | grep -e "http_reqs" -e "http_req_duration"
done
