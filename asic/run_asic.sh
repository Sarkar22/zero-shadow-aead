#!/usr/bin/env bash
# Reproduce the sky130 ASIC results with OpenLane.
#
# Prerequisites (third-party, not included): Docker, OpenLane v1.0.2, and the sky130A PDK
# installed via ciel (PDK_ROOT defaults to ~/.ciel).  See https://github.com/efabless/openlane
#
# Copy the design directory for the configuration you want into
# <OpenLane>/designs/<name>/ , put the RTL from ../rtl (plus any *_top.sv wrapper here)
# into <OpenLane>/designs/<name>/src/ , then run:
set -euo pipefail
: "${OPENLANE_DIR:?set OPENLANE_DIR to your OpenLane checkout}"
: "${DESIGN:?set DESIGN to the design name, e.g. cordic_activation}"
PDK_ROOT="${PDK_ROOT:-$HOME/.ciel}"
IMAGE="${OPENLANE_IMAGE:-ghcr.io/the-openroad-project/openlane:ff5509f65b17bfa4068d5336495ab1718987ff69-amd64}"
docker run --rm -w /openlane \
  -v "$OPENLANE_DIR":/openlane -v "$PDK_ROOT":"$PDK_ROOT" \
  -e PDK_ROOT="$PDK_ROOT" -e PDK=sky130A -e STD_CELL_LIBRARY=sky130_fd_sc_hd \
  "$IMAGE" ./flow.tcl -design "$DESIGN" -tag run1 -overwrite -pdk sky130A
# Results land in <OpenLane>/designs/$DESIGN/runs/run1/ :
#   reports/metrics.csv                 cell count, utilisation, DRC/LVS/antenna counts
#   reports/signoff/*rcx_sta.summary.rpt  post-route setup/hold slack (authoritative)
#   results/final/gds/                  the GDSII
