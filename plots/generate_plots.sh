#!/bin/bash

# Exit on error
set -e

# Arguments passed from CMake
GNUPLOT_EXE=$1
PLOTS_DIR=$2
OUT_DIR=$3

echo "Running gnuplot scripts from: $PLOTS_DIR"

# Plot 1: Threads Over Time
$GNUPLOT_EXE -c "$PLOTS_DIR/threads_over_time.gnuplot" \
    "$OUT_DIR/oncpu_slices.csv" \
    "$OUT_DIR/alive_series.csv" \
    "$OUT_DIR/threads_over_time.pdf"

# Plot 2: CPU Timeline
$GNUPLOT_EXE -c "$PLOTS_DIR/cpu_timeline.gnuplot" \
    "$OUT_DIR/oncpu_slices.csv" \
    "$OUT_DIR/cpu_timeline.pdf"

$GNUPLOT_EXE -c "$PLOTS_DIR/rq_depth_all_cpus.gnuplot" \
     "${OUT_DIR}/oncpu_slices.csv"  \
     "${OUT_DIR}/rq_depth_all_cpus.pdf"

echo "Successfully generated plots in: $OUT_DIR"