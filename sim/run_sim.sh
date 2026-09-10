#!/usr/bin/env bash
# Verify Ascon-AEAD128: golden model against all 1089 official KATs, then the RTL
# against the model at every engine size. Reports the precompute/visible split.
set -e
cd "$(dirname "$0")"
echo "== golden model vs official KATs =="
python3 - <<'PY'
import sys; sys.path.insert(0, "../model")
import ascon_aead as A
assert A.selftest(), "model failed the official Ascon-AEAD128 KATs"
A.emit_vectors()
PY
echo
echo "== RTL vs model, sweeping ROUNDS_PER_CYCLE =="
fail=0
for R in 1 2 3 4 6 8 12; do
    iverilog -g2012 -DRPC=$R -o /tmp/aead_r$R.vvp ../rtl/ascon_aead.sv ../tb/tb_aead.sv 2>/dev/null
    out=$(vvp /tmp/aead_r$R.vvp 2>/dev/null)
    echo "  RPC=$R: $(echo "$out" | grep -oE 'RESULT: [A-Z]+')"
    echo "$out" | grep -q "RESULT: PASS" || fail=1
done
[ $fail -eq 0 ] && echo "ALL CONFIGURATIONS PASS" || { echo "FAILURES"; exit 1; }
