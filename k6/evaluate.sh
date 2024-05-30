#!/bin/bash

for i in {1..15}
do
  echo "vui == ${i}"
  k6 run script.js --vus ${i} | grep -e "http_reqs" -e "http_req_duration"
done
