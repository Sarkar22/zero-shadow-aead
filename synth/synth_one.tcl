# synth+impl ascon_aead at a given (ROUNDS_PER_CYCLE, LANES); append one CSV row.
#   vivado -mode batch -source synth/synth_one.tcl -tclargs <part> <period> <rpc> <lanes>
set part [lindex $argv 0]; set period [lindex $argv 1]
set rpc  [lindex $argv 2]; 
set root [pwd]; set label "shadow_r${rpc}"
set outdir $root/results/synth/$label
file mkdir $outdir
read_verilog -sv $root/rtl/ascon_aead.sv


synth_design -top ascon_aead -part $part -mode out_of_context \
             -generic ROUNDS_PER_CYCLE=$rpc -flatten_hierarchy rebuilt
create_clock -period $period -name clk [get_ports clk]
opt_design; place_design; route_design
report_utilization -file $outdir/util.rpt
report_timing_summary -file $outdir/timing.rpt
report_power -file $outdir/power.rpt
proc ncells {pat} { return [llength [get_cells -hierarchical -filter "REF_NAME =~ $pat"]] }
set luts [ncells LUT*]; set ff [ncells FD*]; set dsp [ncells DSP48*]; set bram [ncells RAMB*]
set wns [get_property SLACK [get_timing_paths -setup -max_paths 1 -nworst 1]]
if {$wns eq ""} { set wns 0.0 }
set fmax [expr {($period-$wns) > 0 ? 1000.0/($period-$wns) : 0.0}]
set power "NA"
if {[catch { set fh [open $outdir/power.rpt r]; set txt [read $fh]; close $fh
    if {[regexp {Total On-Chip Power \(W\)\s*\|\s*([0-9.]+)} $txt -> p]} { set power $p } }]} {}
set csv $root/results/aead_sweep.csv
if {![file exists $csv]} { set fh [open $csv w]
    puts $fh "rpc,part,period_ns,lut,ff,dsp,bram,wns_ns,fmax_mhz,power_w"; close $fh }
set fh [open $csv a]
puts $fh [format "%s,%s,%s,%d,%d,%d,%d,%.3f,%.1f,%s" \
          $rpc $part $period $luts $ff $dsp $bram $wns $fmax $power]
close $fh
puts "==== $label : LUT=$luts FF=$ff DSP=$dsp BRAM=$bram Fmax=${fmax}MHz Power=${power}W"
