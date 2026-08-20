#!/bin/bash
echo "Killing any orphaned processes..."
sudo pkill -9 -f bench_full_matrix 2>/dev/null
sudo killall -9 python3 tcpreplay iperf3 rustiflow loader 2>/dev/null

cd /home/leonardo.herkenhoff/Lynceus
echo "Updating from Git..."
git fetch origin
git pull origin exp-rustiflow

echo "Cleaning previous results..."
rm -f full_matrix_results.csv
echo "timestamp,scenario,target,duration,bitrate,dropped,notes" > full_matrix_results.csv

echo "Provisioning testbed namespace and veth pair..."
sudo ip netns add rustiflow-peer
sudo ip link add rustiflow-t0 type veth peer name rustiflow-p0
sudo ip link set rustiflow-p0 netns rustiflow-peer
sudo ip link set rustiflow-t0 up
sudo ip netns exec rustiflow-peer ip link set rustiflow-p0 up
sudo ip netns exec rustiflow-peer ip link set lo up



echo "Starting Lynceus (Strict Replication)"
sudo python3 scripts/bench_full_matrix.py --target lynceus

echo "Starting Rustiflow (Strict Replication)"
sudo python3 scripts/bench_full_matrix.py --target rustiflow

echo "ALL DONE!"
