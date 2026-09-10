#!/usr/bin/env python3
"""
Ascon-p permutation + Ascon-XOF128 golden model (NIST SP 800-232, little-endian).

This is the executable specification for the RTL core. Constants taken from
SP 800-232 and cross-checked here against the official Known-Answer Tests:
the permutation KATs (Table 12 post-init states), and the Ascon-Hash256 /
Ascon-XOF128 KAT files from github.com/ascon/ascon-c.

Usage in Shadow-LWE: the 128-bit per-ciphertext seed (public) is absorbed as the
message; the squeeze stream is the LWE mask a[0..N-1] (N=630 words of W=32 bits).
"""
MASK = (1 << 64) - 1
RC12 = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
XOF_IV  = 0x0000080000cc0003
HASH_IV = 0x0000080100cc0002

def ror(x, n): return ((x >> n) | (x << (64 - n))) & MASK

def permutation(S, rc=RC12):
    x0, x1, x2, x3, x4 = S
    for c in rc:
        # pC: add round constant into x2
        x2 ^= c
        # pS: 5-bit bitsliced S-box (ascon-c round.h canonical op list)
        x0 ^= x4; x4 ^= x3; x2 ^= x1
        t0 = x0 ^ ((x1 ^ MASK) & x2)
        t1 = x1 ^ ((x2 ^ MASK) & x3)
        t2 = x2 ^ ((x3 ^ MASK) & x4)
        t3 = x3 ^ ((x4 ^ MASK) & x0)
        t4 = x4 ^ ((x0 ^ MASK) & x1)
        t1 ^= t0; t0 ^= t4; t3 ^= t2; t2 ^= MASK
        x0, x1, x2, x3, x4 = t0, t1, t2, t3, t4
        # pL: linear diffusion
        x0 ^= ror(x0, 19) ^ ror(x0, 28)
        x1 ^= ror(x1, 61) ^ ror(x1, 39)
        x2 ^= ror(x2, 1)  ^ ror(x2, 6)
        x3 ^= ror(x3, 10) ^ ror(x3, 17)
        x4 ^= ror(x4, 7)  ^ ror(x4, 41)
    return [x0 & MASK, x1 & MASK, x2 & MASK, x3 & MASK, x4 & MASK]

def _blocks(msg: bytes):
    """64-bit little-endian blocks with 10* padding (always adds a final block)."""
    full = len(msg) // 8
    blks = [int.from_bytes(msg[8*i:8*i+8], "little") for i in range(full)]
    rem = msg[8*full:]
    blks.append(int.from_bytes(rem, "little") ^ (1 << (8*len(rem))))
    return blks

def _sponge(iv, msg: bytes, outlen: int):
    S = permutation([iv, 0, 0, 0, 0])   # initialization: state = p12(IV || 0^256)
    blks = _blocks(msg)
    for i, blk in enumerate(blks):
        S[0] ^= blk
        if i != len(blks) - 1:
            S = permutation(S)          # permute after every block except the last
    out = b""
    while len(out) < outlen:
        S = permutation(S)              # squeeze begins with a permutation
        out += (S[0] & MASK).to_bytes(8, "little")
    return out[:outlen]

def xof128(seed: bytes, outlen: int): return _sponge(XOF_IV, seed, outlen)
def hash256(msg: bytes):              return _sponge(HASH_IV, msg, 32)

def mask_words(seed: bytes, n_words: int, wbits: int = 32):
    """Expand a public seed into n_words of wbits each (the LWE a[] vector)."""
    raw = xof128(seed, (n_words * wbits + 7) // 8)
    v = int.from_bytes(raw, "little")
    m = (1 << wbits) - 1
    return [(v >> (wbits*i)) & m for i in range(n_words)]

# ---------------------------------------------------------------- self-test ---
def _h(words): return [f"0x{w:016x}" for w in words]
def _selftest():
    ok = True
    # (1) permutation KAT: p12(XOF IV || 0^256) == SP 800-232 Table 12 (XOF128)
    t12_xof = [0xda82ce768d9447eb, 0xcc7ce6c75f1ef969, 0xe7508fd780085631,
               0x0ee0ea53416b58cc, 0xe0547524db6f0bde]
    r = permutation([XOF_IV, 0, 0, 0, 0]); ok &= (r == t12_xof)
    print(f"p12(XOF IV)  == Table12 XOF : {r == t12_xof}")
    # (2) permutation KAT: Hash256 init
    t12_hash = [0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a,
                0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d]
    r = permutation([HASH_IV, 0, 0, 0, 0]); ok &= (r == t12_hash)
    print(f"p12(HASH IV) == Table12 Hash: {r == t12_hash}")
    # (3) permutation on all-zero state (deterministic anchor)
    z = [0x78ea7ae5cfebb108, 0x9b9bfb8513b560f7, 0x6937f83e03d11a50,
         0x3fe53f36f2c1178c, 0x045d648e4def12c9]
    r = permutation([0, 0, 0, 0, 0]); ok &= (r == z)
    print(f"p12(all-zero) == anchor     : {r == z}")
    # (4) Ascon-Hash256 official KATs
    h_kats = {
        b"": "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2",
        bytes([0x00]): "0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80",
        bytes([0x00, 0x01]): "6115E7C9C4081C2797FC8FE1BC57A836AFA1C5381E556DD583860CA2DFB48DD2",
    }
    for msg, exp in h_kats.items():
        got = hash256(msg).hex().upper()
        ok &= (got == exp.upper())
        print(f"Hash256({msg.hex() or 'empty':<6}) KAT      : {got == exp.upper()}")
    # (5) Ascon-XOF128 official KATs (512-bit output)
    x_kats = {
        b"": ("473D5E6164F58B39DFD84AACDB8AE42EC2D91FED33388EE0D960D9B3993295C6"
              "AD77855A5D3B13FE6AD9E6098988373AF7D0956D05A8F1665D2C67D1A3AD10FF"),
        bytes([0x00]): ("51430E0438ECDF642B393630D977625F5F337656BA58AB1E960784AC32A16E0D"
                        "446405551F5469384F8EA283CF12E64FA72C426BFEBAEA3AA1529E2C4AB23A2F"),
    }
    for msg, exp in x_kats.items():
        got = xof128(msg, 64).hex().upper()
        ok &= (got == exp.upper())
        print(f"XOF128({msg.hex() or 'empty':<6},512) KAT   : {got == exp.upper()}")
    print("\nALL ASCON KATs PASS" if ok else "\n*** KAT FAILURE ***")
    return ok

if __name__ == "__main__":
    import sys
    sys.exit(0 if _selftest() else 1)

# ------------------------------------------------------------ RTL vectors -----
def emit_vectors(path="tb/ascon_vectors.hex", n_out=8, seeds=None):
    """Emit XOF128 known-answer vectors for the RTL testbench.
    Each line: <seed_hex_32> <n_out 64-bit squeezed words, MSB-first per word>."""
    import os
    if seeds is None:
        seeds = [0, 1, 0xffffffffffffffffffffffffffffffff,
                 0x0f0e0d0c0b0a09080706050403020100,
                 0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5,
                 0xdeadbeefcafebabe0123456789abcdef]
    lines = ["// seed(128b hex) then %d squeezed 64-bit words" % n_out]
    for sd in seeds:
        b = sd.to_bytes(16, "little")
        raw = xof128(b, 8 * n_out)
        words = [int.from_bytes(raw[8*i:8*i+8], "little") for i in range(n_out)]
        lines.append(f"{sd:032x} " + " ".join(f"{w:016x}" for w in words))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = os.path.join(root, path)
    open(p, "w").write("\n".join(lines) + "\n")
    print(f"wrote {path}  ({len(seeds)} seeds x {n_out} words)")

# ------------------------------------------------- Shadow-LWE golden model ----
N_LWE, W_LWE = 630, 32
DELTA = 1 << (W_LWE - 3)
QW    = (1 << W_LWE) - 1

def shadow_lwe_encrypt(seed_int, sk_bits, m_bit, e_val):
    """Seed-compressed LWE: a[] is expanded on chip from the seed, so the
    ciphertext is (seed, b) instead of (a[0..N-1], b).
    Returns (b, a_list) with b = Delta*(+-1) + e + sum sk[i]*a[i]  mod 2^W."""
    a = mask_words(seed_int.to_bytes(16, "little"), N_LWE, W_LWE)
    acc = ((DELTA if m_bit else -DELTA) + e_val) & QW
    for i in range(N_LWE):
        if sk_bits[i]:
            acc = (acc + a[i]) & QW
    return acc, a

def emit_shadow_vectors(path="tb/shadow_vectors.hex", n=6):
    """seed | sk(630b hex) | m | e | expected b."""
    import os, random
    rng = random.Random(7)
    lines = ["// seed(128b) sk(630b) m e(32b signed hex) b(32b)"]
    for k in range(n):
        seed = rng.getrandbits(128)
        sk   = [rng.getrandbits(1) for _ in range(N_LWE)]
        m    = rng.getrandbits(1)
        e    = rng.randint(-(1 << 20), (1 << 20))
        b, _ = shadow_lwe_encrypt(seed, sk, m, e)
        skint = 0
        for i, bit in enumerate(sk):
            skint |= bit << i
        lines.append(f"{seed:032x} {skint:0158x} {m:01x} {e & QW:08x} {b:08x}")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    open(os.path.join(root, path), "w").write("\n".join(lines) + "\n")
    print(f"wrote {path} ({n} vectors)")
