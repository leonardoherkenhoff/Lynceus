#!/bin/bash
echo "Killing any orphaned processes..."
sudo pkill -9 -f run_batch 2>/dev/null
sudo pkill -9 -f bench_full_matrix 2>/dev/null
sudo killall -9 python3 tcpreplay iperf3 rustiflow loader 2>/dev/null

cd /home/leonardo.herkenhoff/Lynceus
echo "Updating from Git..."
git fetch origin
git pull origin exp-rustiflow

echo "Cleaning previous results..."
rm -f full_matrix_results.csv
echo "timestamp,scenario,target,duration,bitrate,dropped,notes" > full_matrix_results.csv

echo "Starting Lynceus GRO ON"
sudo python3 scripts/bench_full_matrix.py --target lynceus --test ALL --gro on
echo "Starting Lynceus GRO OFF"
sudo python3 scripts/bench_full_matrix.py --target lynceus --test ALL --gro off
echo "Starting Rustiflow GRO ON"
sudo python3 scripts/bench_full_matrix.py --target rustiflow --test ALL --gro on
echo "Starting Rustiflow GRO OFF"
sudo python3 scripts/bench_full_matrix.py --target rustiflow --test ALL --gro off

echo "ALL DONE!"
