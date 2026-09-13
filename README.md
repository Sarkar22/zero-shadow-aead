# Ascon-AEAD128 with a Precompute/Visible Schedule Split

A counter-mode keystream can be hidden entirely behind an edge inference, but an authentication tag cannot: it depends on the record. This core exposes the part that *can* still be hidden. Initialization depends only on key and nonce, so it is precomputed during the previous inference and leaves the critical path.

This is the artifact for a paper submitted to **IEEE CCECE 2027** (under review). Every
number below is reproduced by the scripts in this repository.

## Results

- Golden model reproduces **all 1089 official Ascon-AEAD128 known-answer tests** (encryption, decryption round-trip, and rejection of a tampered tag)
- RTL **7/7 bit-exact** against the model at every engine size from 1 to 12 rounds per cycle
- Precomputing initialization removes **33-46%** of a single-block encryption from the critical path
- Sizing by cycle count is misleading: the largest engine minimizes visible *cycles* but is **2.5× slower in wall-clock time** and 3.6× the area, because Fmax collapses
- Recommended point: 2337 LUT, **0 DSP / 0 BRAM**, 307 MHz, 29 ns visible per record

## Reproducing

```bash
bash sim/run_sim.sh   # official KATs, then RTL at every engine size
```
```bash
python3 model/feasibility.py   # schedulability frontier
```
```bash
python3 model/analyze.py   # tables and figures from the sweep
```

```bash
OPENLANE_DIR=/path/to/OpenLane DESIGN=ascon_aead_top bash asic/run_asic.sh   # sky130 RTL-to-GDSII
```

The `asic/` directory holds the OpenLane configuration for each
signed-off configuration; the flow itself is third-party (see Requirements).

## Requirements

Third-party tools, not included here. Any recent version should work; these are what the
reported numbers were produced with.

| tool | used | purpose |
|---|---|---|
| Icarus Verilog | 12.0 | simulation (`iverilog -g2012`) |
| Python 3 | 3.12 + numpy (matplotlib for figures) | golden models and analysis |
| AMD Vivado | 2024.2 | FPGA synthesis and place-and-route |

## Layout

```
model/    Python golden model: the executable specification, and the analysis scripts
rtl/      synthesizable SystemVerilog
tb/       self-checking testbenches
sim/      one-command verification
synth/    Vivado scripts (constraints, sweeps, reporting)
results/  measured CSVs and the figures generated from them
```

## Notes

Parameters follow **NIST SP 800-232**: rate 128 bits with b=8 rounds per data block (the profile formerly called Ascon-128a). The legacy rate-64 / b=6 "Ascon-128" is *not* standardized and will fail these vectors.

Scope: empty associated data, which suits telemetry records carrying no separate header.

`model/LWC_AEAD_KAT_128_128.txt` is the official vector file from [ascon/ascon-c](https://github.com/ascon/ascon-c).

## License

MIT, see [LICENSE](LICENSE).
