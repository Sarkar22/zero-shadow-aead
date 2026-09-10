#!/usr/bin/env python3
"""
Zero-Shadow AEAD feasibility study (pure Python, no RTL).

The secure-edge-node design hides a CTR keystream behind an inference because the
keystream depends only on a counter. Authenticated encryption is harder: the tag
depends on the record itself, so the tag cannot be precomputed. The question is
whether the part that cannot be precomputed still fits somewhere.

Schedule. In a streaming node, record n is finalized when inference n ends, and
inference n+1 then runs for T_inf cycles. So the AEAD work for record n can be
hidden behind the NEXT inference.

Ascon-AEAD128 (NIST SP 800-232): rate 128 b/block, a=12 rounds (init, finalize),
b=8 rounds per data block.
  precomputable (depends only on key+nonce): init          = 12 rounds
  NOT precomputable (depends on the record): 8*M + 12 rounds
where M = blocks in the record.

Hiding condition:   ceil((8M + 12)/R)  <=  T_inf      (R = rounds per cycle)

GO criteria: the frontier must be non-trivial, i.e. small records fit with a
minimal engine but realistic batched records do not, so engine sizing actually
matters. If everything fits at R=1, the paper has no tension and we kill it.
"""
import math

A_ROUNDS, B_ROUNDS, RATE_BITS = 12, 8, 128

def rounds_hidden_part(M):      # data absorb + finalize (cannot be precomputed)
    return B_ROUNDS * M + A_ROUNDS

def rounds_precomputable():     # init from key+nonce only
    return A_ROUNDS

def min_R(M, T_inf):
    """smallest rounds-per-cycle that hides record of M blocks behind T_inf cycles"""
    for R in range(1, 13):
        if math.ceil(rounds_hidden_part(M) / R) <= T_inf:
            return R
    return None

def main():
    print("=== Ascon-AEAD128 work split (rounds) ===")
    for M in (1, 4, 16, 64, 128):
        print(f"  M={M:4d} blocks ({M*RATE_BITS//8:5d} B): "
              f"precomputable {rounds_precomputable():3d} | "
              f"must-wait {rounds_hidden_part(M):5d}")

    print("\n=== minimum engine (rounds/cycle) to hide behind the next inference ===")
    shadows = [32, 64, 111, 256, 512]          # 111 = the measured node inference
    print("   record        " + "".join(f"T={t:<6d}" for t in shadows))
    interesting = 0
    for M in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        cells = []
        for T in shadows:
            R = min_R(M, T)
            cells.append(f"R={R:<4}" if R else "none ")
        row = "".join(f"{c:<8}" for c in cells)
        print(f"  {M:4d} blk ({M*16:5d} B) {row}")
        Rs = [min_R(M, T) for T in shadows]
        if any(r is None for r in Rs) or any(r and r > 1 for r in Rs):
            interesting += 1

    print("\n=== verdict inputs ===")
    triv = all(min_R(M, 111) == 1 for M in (1, 4, 16, 64))
    print(f"  everything fits at R=1 behind the 111-cycle node shadow? {triv}")
    for T in shadows:
        biggest = max((M for M in range(1, 4096) if min_R(M, T)), default=0)
        print(f"  T={T:4d}: largest hideable record = {biggest:4d} blocks "
              f"({biggest*16:6d} B) even at R=12")
    print(f"  rows where sizing matters: {interesting}/9")

if __name__ == "__main__":
    main()
