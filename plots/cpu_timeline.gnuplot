# ============================================================
# CPU Load Heatmap - High Aggregation & Deep Merge (PDF Version)
# ============================================================

if (ARGC < 2) {
    print "Usage: gnuplot -c cpu_timeline.gnuplot <data.csv> <output.pdf>"
    exit
}

input_file = ARG1
output_file = ARG2

set datafile separator ","

# --- PDF TERMINAL SETUP ---
# For PDF, size is in inches. 10in x 4in roughly maps to your previous 1200x400 ratio.
set terminal pdfcairo size 10in, 3.5in enhanced font 'Verdana,10'
set output output_file

# --- AGGREGAZIONE AGGRESSIVA ---
bin_width = 100.0
to_ms(x) = x / 1e6
bin(x) = bin_width * floor(to_ms(x)/bin_width)

# Palette Azzurro -> Rosso
set palette defined (0 "#ADD8E6", 1 "#FF0000")
set cbrange [0:1]
set cblabel "CPU Load"

set title "CPU Load Heatmap" font "Verdana,14,Bold"
set xlabel "Time (ms)"
set ylabel "CPU"

# Detect max CPU id from data
stats input_file skip 1 using ($2) nooutput
maxcpu = int(STATS_max)
if (maxcpu < 0) maxcpu = 0

set yrange [-0.5:maxcpu+0.5]
set ytics 1
set format y "CPU %g"

# Style: noborder is crucial for PDFs to prevent "flickering" lines between blocks
set style fill solid 1.0 noborder

# --- PLOT LOGIC ---
plot \
    for [c=0:maxcpu] c with lines lc rgb "#EEEEEE" lw 1 notitle, \
    for [c=0:maxcpu] input_file skip 1 using \
    ( $2 == c ? bin($4) + bin_width/2.0 : 1/0 ) : \
    ( c ) : \
    ( bin($4) ) : \
    ( bin($4) + bin_width + 0.5 ) : \
    ( c - 0.2 ) : \
    ( c + 0.2 ) : \
    ( to_ms($6) / bin_width ) \
    with boxxyerror lc palette notitle