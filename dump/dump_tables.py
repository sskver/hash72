#!/usr/bin/env python3
"""Extract the hash72 whitebox tables from a firmware image and emit tables.go.

Every table, byte permutation and blend constant is derived from runtime traces by constancy
search - nothing is hardcoded - so the output is reproducible from a firmware image alone and
version drift shows up as a validation failure instead of silently wrong answers.

Supply a firmware image from a device you own. No Apple-derived data is shipped in this repo.
This script does not decrypt anything itself - get a decrypted image with wInd3x
(https://github.com/freemyipod/wInd3x), e.g. `./wInd3x decrypt osos5g.encrypted.osos osos5g.dec`.

usage:
  dump_tables.py --retail osos5g_retail.bin --stub osos5g_stub.bin [-out tables.go]
                 [--samples 3400] [--seed 20261004] [--fit 2400]

The retail half is the image loaded at 0x08000000. With only a combined body, split it at
0x2e27c: the first part is the SRAM stub (loaded at 0x22000000), the rest is retail.
"""
import argparse, random, struct, sys
from unicorn import *
from unicorn.arm_const import *

BASE = 0x08000000
STUB_BASE = 0x22000000
STACK_TOP = 0x30100000
HEAP = 0x31000000
BUF = 0x32000000
DONE = 0x0FFFFFF0

B814 = 0x0837B814          # FUN_0837b814: the fixed-key whitebox AES
B814_BODY = 0x083E85D8     # an address inside its body, bounds the read window
WB_LO, WB_HI = 0x08680000, 0x086A0000
WRAPPER = 0x0836749C       # the signature wrapper; it supplies the whitebox key at runtime

LADDER = {}                # holds the limb unscale factor, set before any bignum decode

# Read order inside one whitebox call, established by the original trace work:
#   [0..15]    input table reads
#   [16..159]  9 rounds x 16 slots of 4-byte T-table reads
#   [160..175] final table reads
N_READS = 192


class Emu:
    def __init__(self, retail, stub):
        mu = self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu.mem_map(BASE, 0x04000000)
        mu.mem_write(BASE, retail)
        mu.mem_map(STUB_BASE, 0x100000)
        mu.mem_write(STUB_BASE, stub[:0x100000])
        mu.mem_map(STACK_TOP - 0x100000, 0x100000)
        mu.mem_map(HEAP, 0x400000)
        mu.mem_map(BUF, 0x100000)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self._lazy)
        rd = lambda a: struct.unpack('<I', self.read(a, 4))[0]
        heap_obj = self.call(0x08264964, [rd(0x082724b0), rd(0x082724b4)], thumb=True)
        mu.mem_write(rd(0x082724ac), struct.pack('<I', heap_obj))
        self.call(0x08196860, [heap_obj, HEAP, 0x400000, 0], thumb=True)

    def _lazy(self, uc, access, addr, size, value, ud):
        uc.mem_map(addr & ~0xFFF, 0x1000)
        return True

    def read(self, a, n):
        return bytes(self.mu.mem_read(a, n))

    def write(self, a, b):
        self.mu.mem_write(a, bytes(b))

    def call(self, fn, args, thumb=False, count=20_000_000):
        mu = self.mu
        for i, a in enumerate(args[:4]):
            mu.reg_write(UC_ARM_REG_R0 + i, a)
        mu.reg_write(UC_ARM_REG_SP, STACK_TOP - 0x8000)
        mu.reg_write(UC_ARM_REG_LR, DONE | (1 if thumb else 0))
        mu.emu_start(fn | (1 if thumb else 0), DONE, count=count)
        return mu.reg_read(UC_ARM_REG_R0)


def discover_firmware_values(e):
    """Run the real wrapper once and take the key and the ladder constants out of it.

    The key is not plaintext in the image - FUN_083b1e90 rebuilds it from obfuscated bytes with an
    affine map - and the ladder's modulus pointer is likewise supplied by the wrapper at runtime.
    So hook both places during one wrapper run rather than passing our own buffers, which would
    just measure our own input back at us.
    """
    got = {}

    def grab_key(uc, addr, size, ud):
        if addr != B814 or 'key' in got:
            return
        got['key'] = bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R2), 16))
        if 'lad' in got:
            uc.emu_stop()

    def grab_ladder(uc, addr, size, ud):
        if addr != MODEXP_INIT_END or 'lad' in got:
            return
        sp = uc.reg_read(UC_ARM_REG_SP)
        raw = {}
        for name, off in (('N', 0x2c), ('M', 0x04), ('cst', 0x11c), ('red', 0x0f0)):
            raw[name] = [struct.unpack('<I', bytes(uc.mem_read(sp + off + 4 * i, 4)))[0]
                         for i in range(5)]
        got['lad'] = raw
        if 'key' in got:
            uc.emu_stop()

    def on_any(uc, addr, size, ud):
        last['pc'] = addr
        last['n'] += 1

    last = {'pc': 0, 'n': 0}
    # A nonzero identity and a plausible signature header: the wrapper bails out before it ever
    # reaches the whitebox if handed an empty identity.
    e.write(BUF + 0, struct.pack('<I', 8) + bytes.fromhex('0102030405060708') + bytes(12))
    e.write(BUF + 0x100, bytes(20))
    e.write(BUF + 0x200, bytes([1, 0]) + bytes(44))
    e.write(0x300fed00, bytes(0x200))
    sp = STACK_TOP - 0x1000
    e.mu.mem_write(sp, struct.pack('<III', 0x14, BUF + 0x200, 0x2e))
    mu = e.mu
    mu.reg_write(UC_ARM_REG_SP, sp)
    for i, v in enumerate((0, BUF, 0x18, BUF + 0x100)):
        mu.reg_write(UC_ARM_REG_R0 + i, v)
    mu.reg_write(UC_ARM_REG_LR, DONE)

    hk = mu.hook_add(UC_HOOK_CODE, grab_key, begin=B814, end=B814 + 4)
    hl = mu.hook_add(UC_HOOK_CODE, grab_ladder, begin=MODEXP_INIT_END, end=MODEXP_INIT_END + 4)
    ha = mu.hook_add(UC_HOOK_CODE, on_any, begin=BASE, end=BASE + 0x700000)
    try:
        mu.emu_start(WRAPPER, DONE, count=50_000_000)
    except UcError as ex:
        for h in (hk, hl, ha):
            mu.hook_del(h)
        raise SystemExit(f'wrapper run failed: {ex} (last pc {last["pc"]:#08x})')
    for h in (hk, hl, ha):
        mu.hook_del(h)

    if 'key' not in got:
        raise SystemExit(f'wrapper ran {last["n"]} instructions and never reached {B814:#x} '
                         f'(stopped at pc {last["pc"]:#08x}) - is this the retail half loaded at '
                         f'0x08000000?')
    if 'lad' not in got:
        raise SystemExit(f'wrapper never reached the ladder at {MODEXP_INIT_END:#08x}')
    return got['key'], got['lad']


def trace(e, data, key):
    """One whitebox call: return (out16, table reads)."""
    st = {'active': False, 'ret': None}
    reads = []

    def on_code(uc, addr, size, ud):
        if addr == B814_BODY:
            st['active'] = True
            st['ret'] = uc.reg_read(UC_ARM_REG_LR) & ~1
        elif st['active'] and addr == st['ret']:
            st['active'] = False

    def on_read(uc, access, addr, size, value, ud):
        if st['active'] and WB_LO <= addr < WB_HI:
            reads.append((addr, size))

    e.write(BUF + 0x100, data)
    e.write(BUF + 0x200, key)
    hk = e.mu.hook_add(UC_HOOK_CODE, on_code, begin=BASE, end=BASE + 0x700000)
    hr = e.mu.hook_add(UC_HOOK_MEM_READ, on_read)
    e.call(B814, [BUF + 0x300, BUF + 0x100, BUF + 0x200, 0])
    out = e.read(BUF + 0x300, 16)
    e.mu.hook_del(hk)
    e.mu.hook_del(hr)
    return out, reads


MODEXP = 0x08372998          # FUN_08372998: the ladder
MODEXP_INIT_END = 0x08372A6C  # just after its buffer initialisation, before the loop
BBA94 = 0x083BBA94           # FUN_083bba94: bignum loader, applies the byte transform
DAT_LIMB_SCALE = 0x083BBBC8  # every stored bignum word is multiplied by this


def decode_bn(words):
    """Unscale and assemble a firmware bignum: word[0] = limb count, word[1..] LSB-first."""
    cnt = (words[0] * LADDER['inv']) % (1 << 32)
    if cnt >= 0x80000000:
        cnt -= 1 << 32
    limbs = [(w * LADDER['inv']) % (1 << 32) for w in words[1:]]
    v = 0
    for i in range(abs(cnt)):
        v |= limbs[i] << (32 * i)
    return v if cnt >= 0 else -(v % (1 << (32 * abs(cnt))))


def decode_ladder(raw):
    """Unscale the ladder frame buffers captured from the running wrapper."""
    out = {k: decode_bn(v) for k, v in raw.items()}
    out['scale'] = LADDER['scale']
    if out['N'] != (1 << 128) - out['red']:
        raise SystemExit(f'ladder constants inconsistent: N={out["N"]:#x} but 2^128-{out["red"]:#x}')
    return out


def derive_affine(e):
    """Recover the firmware's byte transform by running it on a known input.

    FUN_083bba94 maps each source byte through an affine map before assembling the bignum, so
    feeding 00 01 02 .. 0f and unscale-reading the result gives T(0)..T(15) directly.
    """
    src = BUF + 0x500
    dst = BUF + 0x400
    e.write(src, bytes(range(16)))
    e.write(dst, bytes(20))
    e.call(BBA94, [dst, 16, src])
    words = [struct.unpack('<I', e.read(dst + 4 * i, 4))[0] for i in range(5)]
    val = decode_bn(words)
    tb = val.to_bytes(16, 'big')
    a = (tb[1] - tb[0]) % 256
    b = tb[0]
    if not all((a * i + b) % 256 == tb[i] for i in range(16)):
        raise SystemExit(f'byte transform is not affine: {[t for t in tb]}')
    ia = pow(a, -1, 256)
    return {'decA': a, 'decB': b, 'encA': ia, 'encB': (-b * ia) % 256}


def derive_bases(all_reads):
    """Take the minimum observed address per read group across ALL samples.

    A single call only touches 16 of the 256 entries of a byte table, so its minimum is not
    the base. Across thousands of calls index 0 is reached for every group.
    """
    inp, rnd, fin = [], [], []
    for reads in all_reads:
        if len(reads) != N_READS:
            raise SystemExit(f'expected {N_READS} table reads, got {len(reads)}')
        inp += [a for a, _ in reads[:16]]
        rnd += [a for a, _ in reads[16:160]]
        fin += [a for a, _ in reads[160:176]]
    TB = min(rnd) & ~3
    if max(rnd) - TB >= 0x1000:
        raise SystemExit(f'T-table span is {max(rnd) - TB:#x}, expected < 0x1000')
    INB, FINB = min(inp), min(fin)
    # Each group is 16 per-slot byte tables of 256 entries, so the group spans < 0x1000.
    for name, vals in (('input', inp), ('final', fin)):
        span = max(vals) - min(vals)
        if span >= 0x1000:
            raise SystemExit(f'{name} table group span is {span:#x}, expected < 0x1000')
    return TB, INB, FINB


def parse(reads, TB, INB, FINB):
    if len(reads) != N_READS:
        raise SystemExit(f'expected {N_READS} table reads, got {len(reads)}')
    rounds = []
    for r in range(9):
        g = []
        for i in range(16):
            off = reads[16 + 16 * r + i][0] - TB
            g.append((off // 0x400, (off % 0x400) // 4))
        rounds.append(g)
    fin = [a - FINB for a, _ in reads[160:176]]
    inidx = [a - INB for a, _ in reads[:16]]
    for name, vals in (('input', inidx), ('final', fin)):
        for v in vals:
            if not 0 <= v < 0x1000:
                raise SystemExit(f'{name} table offset {v:#x} out of range - wrong base')
    return rounds, fin, inidx


def const_map(vals):
    v = vals[0]
    return v if all(x == v for x in vals) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--retail', required=True, help='firmware half loaded at 0x08000000')
    ap.add_argument('--stub', required=True, help='SRAM stub loaded at 0x22000000')
    ap.add_argument('--out', default='tables.go')
    ap.add_argument('--samples', type=int, default=3400)
    ap.add_argument('--seed', type=int, default=20261004)
    ap.add_argument('--fit', type=int, default=2400, help='samples used to fit; the rest validate')
    args = ap.parse_args()

    retail = open(args.retail, 'rb').read()
    stub = open(args.stub, 'rb').read()
    if len(retail) < 0x6A0000:
        raise SystemExit('retail image too small to contain the whitebox region '
                         '(is this the retail half, not the combined body?)')

    random.seed(args.seed)
    e = Emu(retail, stub)

    LADDER['scale'] = struct.unpack('<I', e.read(DAT_LIMB_SCALE, 4))[0]
    LADDER['inv'] = pow(LADDER['scale'], -1, 1 << 32)

    key, raw_lad = discover_firmware_values(e)
    print(f'firmware-supplied whitebox key: {key.hex()}', flush=True)

    lad = decode_ladder(raw_lad)
    print(f'ladder limb scale: {lad["scale"]:#08x}')
    print(f'  N    = {lad["N"]:032x}')
    print(f'  M    = {lad["M"]:032x}')
    print(f'  cst  = {lad["cst"]:#x}')
    print(f'  2^128 mod N = {lad["red"]}')

    aff = derive_affine(e)
    print(f'byte transform: T(x) = ({aff["decA"]}x + {aff["decB"]}) mod 256')
    print(f'its inverse:    S(x) = ({aff["encA"]}x + {aff["encB"]}) mod 256')

    print(f'tracing {args.samples} inputs through {B814:#x} ...', flush=True)
    ins, outs, parsed = [], [], []
    for n in range(args.samples):
        d = bytes(random.getrandbits(8) for _ in range(16))
        out, reads = trace(e, d, key)
        ins.append(d)
        outs.append(out)
        parsed.append(reads)
        if (n + 1) % 500 == 0:
            print(f'  {n + 1}/{args.samples}', flush=True)

    lens = {len(r) for r in parsed}
    if len(lens) != 1:
        raise SystemExit(f'varying read counts {lens} - the whitebox branches on the input')
    print(f'all samples made {lens.pop()} table reads')

    TB, INB, FINB = derive_bases(parsed)
    BB = WB_LO
    blob = retail[BB - BASE: BB - BASE + (WB_HI - BB)]

    def u32le(a):
        return struct.unpack('<I', blob[a - BB:a - BB + 4])[0]

    T0 = list(blob[INB - BB:INB - BB + 256])
    FinT = list(blob[FINB - BB:FINB - BB + 256])
    TT = [[u32le(TB + k * 0x400 + 4 * idx) for idx in range(256)] for k in range(4)]
    print(f'TB={TB:#08x} INB={INB:#08x} FINB={FINB:#08x}')

    P = [parse(r, TB, INB, FINB) for r in parsed]

    def R(s, r):
        return P[s][0][r]

    def CB(grp):
        bs = []
        for c in range(4):
            v = 0
            for t in range(4):
                k, idx = grp[4 * c + t]
                v ^= TT[k][idx]
            bs += [v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]
        return bs

    fit = list(range(args.fit))
    held = list(range(args.fit, len(ins)))

    tabs = []
    for r in range(9):
        row = []
        for i in range(16):
            v = const_map([R(s, r)[i][0] for s in fit])
            if v is None:
                raise SystemExit(f'round {r} slot {i}: table choice varies with the input')
            row.append(v)
        tabs.append(row)
    k1, tabsN = tabs[0], tabs[1]
    for r in range(2, 9):
        if tabs[r] != tabsN:
            raise SystemExit(f'round {r} table selection differs from round 1 - unexpected structure')
    print('k1    =', k1)
    print('tabsN =', tabsN)

    p1, c1 = [None] * 16, [None] * 16
    for i in range(16):
        for j in range(16):
            v = const_map([R(s, 0)[i][1] ^ T0[ins[s][j]] for s in fit])
            if v is not None:
                p1[i], c1[i] = j, v
                break
        if p1[i] is None:
            raise SystemExit(f'could not resolve the input byte feeding slot {i}')
    if sorted(p1) != list(range(16)):
        raise SystemExit(f'p1 is not a permutation: {p1}')
    print('p1    =', p1)
    print('c1    =', c1)

    def fit_blend(next_idx, cur_val):
        """next_idx(s, jj) ^ cur_val(s, m) constant -> (perm[jj], key[jj])."""
        perm, key = [None] * 16, [None] * 16
        for jj in range(16):
            for m in range(16):
                v = const_map([next_idx(s, jj) ^ cur_val(s, m) for s in fit])
                if v is not None:
                    perm[jj], key[jj] = m, v
                    break
            if perm[jj] is None:
                raise SystemExit(f'could not resolve the source index for slot {jj}')
        if sorted(perm) != list(range(16)):
            raise SystemExit(f'blend permutation is not a permutation: {perm}')
        return perm, key

    cbs = [[CB(R(s, r)) for s in fit] for r in range(9)]

    Ks = []
    permMid = None
    for r in range(8):
        perm, blend = fit_blend(lambda s, jj, r=r: R(s, r + 1)[jj][1],
                                lambda s, m, r=r: cbs[r][s][m])
        if permMid is None:
            permMid = perm
        elif perm != permMid:
            raise SystemExit(f'round {r} blend permutation differs from round 0 - unexpected structure')
        Ks.append(blend)

    Pm9, K9 = fit_blend(lambda s, i: P[s][1][i], lambda s, m: cbs[8][s][m])
    print('Pm    =', permMid)
    print('Pm9   =', Pm9)

    G = [[None] * 256 for _ in range(16)]
    conflicts = 0
    for s in fit:
        fin = [cbs[8][s][Pm9[i]] ^ K9[i] for i in range(16)]
        for i in range(16):
            if G[i][fin[i]] is not None and G[i][fin[i]] != outs[s][i]:
                conflicts += 1
            G[i][fin[i]] = outs[s][i]
    cov = [sum(1 for v in row if v is not None) for row in G]
    print('output coverage:', cov, 'conflicts:', conflicts)
    if conflicts or min(cov) < 256:
        raise SystemExit('output tables incomplete or contradictory - raise --samples')

    def cipher(pt):
        I = [T0[pt[p1[i]]] ^ c1[i] for i in range(16)]
        for r in range(9):
            sel = k1 if r == 0 else tabsN
            bs = []
            for c in range(4):
                v = 0
                for t in range(4):
                    v ^= TT[sel[4 * c + t]][I[4 * c + t]]
                bs += [v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]
            if r < 8:
                I = [bs[permMid[jj]] ^ Ks[r][jj] for jj in range(16)]
            else:
                f = [bs[Pm9[i]] ^ K9[i] for i in range(16)]
                return bytes(G[i][f[i]] for i in range(16))
        return None

    ok = sum(cipher(ins[s]) == outs[s] for s in held)
    print(f'held-out validation: {ok}/{len(held)} exact')
    if ok != len(held):
        raise SystemExit('VALIDATION FAILED - refusing to emit tables')

    emit_go(args.out, T0, c1, K9, p1, k1, tabsN, permMid, Pm9, Ks, G, TT, TB, INB, FINB, lad, aff, key)
    print('wrote', args.out)


def emit_go(path, T0, c1, K9, p1, k1, tabsN, permMid, permLast, Ks, G, TT, TB, INB, FINB, lad, aff, key):
    L = ['package main', '',
         'import "math/big"',
         '',
         '// generated by dump/dump_tables.py from a firmware image you supply. do not hand edit.',
         '// nothing here is hardcoded: the key and ladder constants are read out of the running',
         '// firmware, the bases come from observed reads, and the rest is solved from traces.',
         f'const wbKeyHex = "{key.hex()}"',
         f'const ladderNHex = "{lad["N"]:032x}"',
         f'const ladderMHex = "{lad["M"]:032x}"',
         f'var ladderCst = big.NewInt({lad["cst"]})',
         f'var ladderReduce = big.NewInt({lad["red"]})',
         f'const decA, decB = {aff["decA"]}, {aff["decB"]}',
         f'const encA, encB = {aff["encA"]}, {aff["encB"]}',
         '']

    def flat(name, vals, typ):
        L.append('')
        L.append(f'var {name} = [...]{typ}{{')
        for i in range(0, len(vals), 16):
            L.append('\t' + ', '.join(str(v) for v in vals[i:i + 16]) + ',')
        L.append('}')

    def matrix(name, rows, typ):
        L.append('')
        L.append(f'var {name} = [...][{len(rows[0])}]{typ}{{')
        for r in rows:
            L.append('\t{' + ', '.join(str(v) for v in r) + '},')
        L.append('}')

    flat('t0Input', T0, 'uint8')
    flat('c1', c1, 'uint8')
    flat('p1', p1, 'uint8')
    flat('k1', k1, 'uint8')
    flat('tabsN', tabsN, 'uint8')
    flat('permMid', permMid, 'uint8')
    flat('permLast', permLast, 'uint8')
    flat('k9', K9, 'uint8')
    matrix('ks', Ks, 'uint8')
    matrix('gOut', G, 'uint8')
    matrix('tt', TT, 'uint32')
    open(path, 'w').write('\n'.join(L) + '\n')


if __name__ == '__main__':
    main()
