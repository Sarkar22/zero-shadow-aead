#!/usr/bin/env python3
"""
Ascon-AEAD128 golden model (NIST SP 800-232), little-endian.

Executable specification for the RTL. Reuses the permutation already verified against
the official Ascon KATs. Parameters (SP 800-232 Table 13): rate 128 b, a=12 rounds for
initialization and finalization, b=8 rounds for data processing. This is the profile
formerly called Ascon-128a; the legacy rate-64/b=6 "Ascon-128" is NOT standardized.

Traps this model encodes explicitly (each is a silent-failure source in RTL):
  * empty AD absorbs NOTHING and runs no permutation (asymmetric with plaintext)
  * domain separation flips the MSB of S4 (little-endian), not the LSB
  * no permutation after the final plaintext block
  * three different key-XOR offsets: init end S3,S4 / final start S2,S3 / tag S3,S4
  * decryption must CLEAR then INSERT the final partial block, not XOR it
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ascon import permutation, MASK, RC12

RC8   = RC12[4:]                       # last 8 constants = p8 schedule
IV    = 0x00001000808c0001             # SP 800-232 Table 14
RATE  = 16                             # bytes
DSEP  = 0x8000000000000000             # domain separation: MSB of S4

def p12(S): return permutation(S, RC12)
def p8(S):  return permutation(S, RC8)

def _le(b):  return int.from_bytes(b, "little")
def _st(w):  return (w & MASK).to_bytes(8, "little")

def _absorb_rate(S, blk16):
    S[0] ^= _le(blk16[0:8]); S[1] ^= _le(blk16[8:16])

def _pad_partial(S, rem):
    """XOR a partial (<16 B) block plus its 10* pad into the rate."""
    n = len(rem)
    if n >= 8:
        S[0] ^= _le(rem[0:8]); S[1] ^= _le(rem[8:n]); S[1] ^= 0x01 << (8 * (n - 8))
    else:
        S[0] ^= _le(rem[0:n]); S[0] ^= 0x01 << (8 * n)

def _init(key: bytes, nonce: bytes):
    k0, k1 = _le(key[0:8]), _le(key[8:16])
    S = [IV, k0, k1, _le(nonce[0:8]), _le(nonce[8:16])]
    S = p12(S)
    S[3] ^= k0; S[4] ^= k1                 # key addition ending initialization
    return S, k0, k1

def _absorb_ad(S, ad: bytes):
    if len(ad) > 0:                        # empty AD: absorb nothing, permute never
        full = len(ad) // RATE
        for i in range(full):
            _absorb_rate(S, ad[RATE*i:RATE*(i+1)]); S[:] = p8(S)
        _pad_partial(S, ad[RATE*full:]);    S[:] = p8(S)
    S[4] ^= DSEP                           # domain separation, always

def encrypt(key: bytes, nonce: bytes, ad: bytes, pt: bytes):
    S, k0, k1 = _init(key, nonce)
    _absorb_ad(S, ad)
    ct = bytearray()
    full = len(pt) // RATE
    for i in range(full):                  # full blocks
        _absorb_rate(S, pt[RATE*i:RATE*(i+1)])
        ct += _st(S[0]) + _st(S[1])
        S[:] = p8(S)
    rem = pt[RATE*full:]                   # final block, always, no permutation after
    _pad_partial(S, rem)
    ct += (_st(S[0]) + _st(S[1]))[:len(rem)]
    S[2] ^= k0; S[3] ^= k1                 # key addition starting finalization
    S[:] = p12(S)
    tag = _st(S[3] ^ k0) + _st(S[4] ^ k1)
    return bytes(ct), tag

def decrypt(key: bytes, nonce: bytes, ad: bytes, ct: bytes, tag: bytes):
    S, k0, k1 = _init(key, nonce)
    _absorb_ad(S, ad)
    pt = bytearray()
    full = len(ct) // RATE
    for i in range(full):
        c = ct[RATE*i:RATE*(i+1)]
        c0, c1 = _le(c[0:8]), _le(c[8:16])
        pt += _st(S[0] ^ c0) + _st(S[1] ^ c1)
        S[0], S[1] = c0, c1                # replace, not XOR
        S[:] = p8(S)
    rem = ct[RATE*full:]
    n = len(rem)
    ks = (_st(S[0]) + _st(S[1]))
    pt += bytes(a ^ b for a, b in zip(rem, ks[:n]))
    # clear the low n bytes of the rate, insert the ciphertext, then pad
    r = bytearray(ks); r[:n] = rem      # low n bytes <- ciphertext, rest stays keystream
    S[0] = _le(bytes(r[0:8])); S[1] = _le(bytes(r[8:16]))
    if n >= 8: S[1] ^= 0x01 << (8 * (n - 8))
    else:      S[0] ^= 0x01 << (8 * n)
    S[2] ^= k0; S[3] ^= k1
    S[:] = p12(S)
    t = _st(S[3] ^ k0) + _st(S[4] ^ k1)
    return (bytes(pt), True) if t == tag else (None, False)

# ------------------------------------------------------------------ KATs ------
def selftest(path=None):
    """Verify against the official LWC_AEAD_KAT_128_128 vectors."""
    path = path or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "LWC_AEAD_KAT_128_128.txt")
    if not os.path.exists(path):
        print(f"KAT file missing: {path}"); return False
    ok = n = 0
    cur = {}
    for line in open(path):
        line = line.strip()
        if not line:
            if cur.get("Count"):
                key = bytes.fromhex(cur["Key"]); non = bytes.fromhex(cur["Nonce"])
                pt  = bytes.fromhex(cur["PT"]);  ad  = bytes.fromhex(cur["AD"])
                exp = bytes.fromhex(cur["CT"])
                c, t = encrypt(key, non, ad, pt)
                n += 1
                if c + t == exp:
                    p, good = decrypt(key, non, ad, c, t)
                    bad = decrypt(key, non, ad, c, bytes([t[0] ^ 1]) + t[1:])[1]
                    if good and p == pt and not bad: ok += 1
                cur = {}
            continue
        k, _, v = line.partition("=")
        cur[k.strip()] = v.strip()
    print(f"Ascon-AEAD128 KATs: {ok}/{n} exact (encrypt + decrypt + tag rejection)")
    return ok == n and n > 0

if __name__ == "__main__":
    sys.exit(0 if selftest() else 1)

# ------------------------------------------------------------ RTL vectors -----
def emit_vectors(path="tb/aead_vectors.hex", lens=(0, 5, 16, 21, 32, 48, 64)):
    """key | nonce | nblocks | bytes_last | pt blocks | ct blocks | tag  (empty AD)."""
    import os, random
    rng = random.Random(11)
    lines = ["// key nonce nblk lastbytes | pt[nblk] | ct[nblk] | tag"]
    for L in lens:
        key = bytes(rng.getrandbits(8) for _ in range(16))
        non = bytes(rng.getrandbits(8) for _ in range(16))
        pt  = bytes(rng.getrandbits(8) for _ in range(L))
        ct, tag = encrypt(key, non, b"", pt)
        # full blocks plus one final (possibly empty) padded block, per spec
        nblk  = L // RATE + 1
        lastb = L % RATE
        def blks(buf):
            out = []
            for i in range(nblk):
                chunk = buf[RATE*i:RATE*(i+1)].ljust(RATE, b"\0")
                out.append(f"{int.from_bytes(chunk,'little'):032x}")
            return out
        lines.append(f"{int.from_bytes(key,'little'):032x} "
                     f"{int.from_bytes(non,'little'):032x} {nblk:02x} {lastb:02x} "
                     + " ".join(blks(pt)) + " " + " ".join(blks(ct)) + " "
                     + f"{int.from_bytes(tag,'little'):032x}")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    open(os.path.join(root, path), "w").write("\n".join(lines) + "\n")
    print(f"wrote {path} ({len(lens)} vectors, PT lengths {lens})")
