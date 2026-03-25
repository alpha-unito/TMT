# ============================================================
# Threads & CPU Activity - Refactored PDF Multi-Color Version
# ============================================================

if (ARGC < 3) {
    print "Usage: gnuplot -c threads_over_time.gp <oncpu.csv> <alive.csv> <output.pdf>"
    exit
}

oncpu_file = ARG1
alive_file = ARG2
outfile    = ARG3

set datafile separator ","

# --- PDF TERMINAL SETUP ---
# PDF sizes are in inches. 10x5 is a good balance for wide timelines.
set terminal pdfcairo size 10in, 5in enhanced font 'Verdana,10'
set output outfile

# --- DATA ANALYSIS ---
stats alive_file using ($1/1e9) nooutput
tmin = STATS_min
tmax = STATS_max
# Ensure a valid range if data is sparse
if (tmax <= tmin) { tmax = tmin + 1.0 }

stats oncpu_file skip 1 using ($2) nooutput
maxcpu = int(STATS_max)
if (maxcpu < 0) { maxcpu = 0 }

# --- BINNING CONFIG ---
nbins     = 100.0
binwidth  = (tmax - tmin) / nbins
bin(x)    = tmin + binwidth * floor((x - tmin) / binwidth) + (binwidth / 2.0)

# --- MULTIPLOT LAYOUT ---
# margins: <left>, <right>, <bottom>, <top>
set multiplot layout 2,1 title "{/:Bold Thread Population vs. CPU Scheduling Activity}" \
    margins 0.1, 0.88, 0.1, 0.90 spacing 0.08

# --- 1. TOP PANEL: Alive Threads ---
set xrange [tmin:tmax]
set format x ""           # Hide xtics for the top panel to save space
set ylabel "Alive Threads"
set grid lc rgb "#DDDDDD"
set key top left

plot alive_file using ($1/1e9):2 \
    with steps lw 2.5 lc rgb "#CC7700" title "Active Thread Count"

# --- 2. BOTTOM PANEL: Scheduling Activity ---
set format x "%g"         # Restore xtics for the bottom panel
set xlabel "Time (seconds)"
set ylabel "Events/Bin"
set grid lc rgb "#DDDDDD"

# Discrete Palette for CPUs (Standard qualitative colors)
set palette defined ( \
    0 "#1f77b4", 1 "#ff7f0e", 2 "#2ca02c", 3 "#d62728", \
    4 "#9467bd", 5 "#8c564b", 6 "#e377c2", 7 "#7f7f7f" )
set cbrange [0:maxcpu > 0 ? maxcpu : 1]
unset colorbox

set style fill solid 0.8 noborder
set boxwidth binwidth * 0.95

# Move legend outside to the right so it doesn't overlap the data
set key outside right center font ",8" title "CPU Core"

plot for [c=0:maxcpu] \
    oncpu_file skip 1 using (bin($4/1e9)):(($2==c)?1:1/0) smooth freq \
    with boxes lc palette cb c title sprintf("CPU %d", c)

unset multiplot