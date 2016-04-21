#!/bin/bash
rm -rf /var/run/snabb/link/*
make -j
./snabb gc

RULES1='[{"filter":"udp src port 53","pps_rate":1000,"pps_burst_rate":2000}]'
RULES2='[{"filter":"dst net 185.64.252.0\/24 and udp src port 53","pps_rate":1000,"pps_burst_rate":2000}]'
RULES3='[{"filter":"dst net 185.64.253.0\/24 and udp src port 53","pps_rate":1000,"pps_burst_rate":2000}]'
RULES4='[{"filter":"dst net 185.64.254.0\/24 and udp src port 53","pps_rate":1000,"pps_burst_rate":2000}]'

./snabb snsh program/ddostop/distributor.lua 4 1 &
./snabb snsh program/ddostop/processor.lua 1 "$RULES1" 1 &
./snabb snsh program/ddostop/processor.lua 2 "$RULES2" 2 &
./snabb snsh program/ddostop/processor.lua 3 "$RULES3" 3 &
./snabb snsh program/ddostop/processor.lua 4 "$RULES4" 4 &

wait

for j in $(jobs -pr); do
   kill $j
done

./snabb gc

