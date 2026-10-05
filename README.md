# hash72

derives an ipod nano 5G `hash72` signature from the device guid alone. no hashinfo, no captured
signature, no itunes, no third-party generator.

this is about interoperability: letting third-party software update a signed `Locations.itdb` on a
device its owner already has (e.g. a user who wants to update their iPod's library without using iTunes). hash72 is not access control over content - it is an integrity check
over a database file, everything on the device is already readable - and the aes key used for the
last step is the libgpod public key, published for twenty years.

## features

- `hash72 GUID16` prints a valid `(rnd12, iv16)` pair, and nothing but the guid is needed to make it
- the pair is file-independent, so it can be cached per device and reused for any library
- `-itdb FILE` computes the digest from the actual file and writes a finished 166-byte cbk
- `dump/` regenerates every table and constant from a firmware image you supply, so nothing
  extracted from apple's binary is shipped here
- the whitebox aes and the ladder behind it are reimplemented from scratch, validated against
  signatures apple's own itunes produced for a real device

## build

needs go 1.26+ and, for the first step only, python 3 with `unicorn`.

```bash
make tables FIRMWARE=/path/to/extracted/firmware/
make build
make test
```

`tables.go` is generated and gitignored. Once it exists the tool needs no firmware, no emulator and
no python.

## usage

```bash
./hash72 0102030405060708
```

```
guid  0102030405060708
rnd   00112233445566778899aabb
iv    447e5140f0721387928733d59fd60028
```

`rnd` comes from the OS CSPRNG unless `-rnd HEX24` is given.

```bash
./hash72 -itdb "iPod_Control/iTunes/iTunes Library.itlp/Locations.itdb" \
         -out Locations.itdb.cbk 0102030405060708
./hash72 -digest HEX40 -rnd HEX24 0102030405060708   # sign a SHA1 you already know
./hash72 -uuid 0102030405060708                      # also print a libgpod-style HashInfo
```

## how it works

```
in0  = S(guid8 || rnd12[0:8])                       S(x) = (a*x + b) mod 256, a firmware-specific
o0   = whitebox_aes(in0)                            FUN_0837b814, fixed key                affine map
v    = int_bigendian(T(o0)) mod N                   T = S's inverse; N = 2^128 - k
s    = (rnd12[8] + rnd12[9] + rnd12[10] + rnd12[11]) mod 17
iv   = ladder(v, 13 + s)                            FUN_08372998
ct32 = AES-128-CBC(pubkey, iv)(digest || rnd12)
sig  = 01 00 || rnd12 || ct32
cbk  = sig || digest || SHA1(each 1024-byte block of the file)
```

`a`, `b`, `k` and the ladder constants below are all recovered from your own firmware by
`dump/dump_tables.py` at build time (see "what is not shipped") - they are not printed here since
they're specific values pulled from Apple's binary, not part of the algorithm's shape.

the digest is `SHA1(concat(SHA1(each 1024-byte block)))`, computed from the file, never supplied by
hand. the iv does not depend on the digest at all, which is why a pair works for any library.

`ladder` is a two-register recurrence over `GF(N)`, using Montgomery multiplication
`mont(a,b) = a*b*2^-128 mod N`, with `N`, `M` and `cst` recovered per-build the same way:

```
A0 = M    C0 = v
A' = cst*(A*A) - cst*(C*C) + M
C' = 2*cst*(C*A) + v
iv = C after (13 + s) iterations
```

the firmware runs the whitebox three times per signature (`in0`, `in1`, `in2`) and each output
produces an iv the verifier accepts - it compares after every round and stops on the first match.
this tool uses the `in0` branch, which is the one whose ivs match what itunes, MusicBee and
ihash.marcan.st produce.

## dump/

`dump/dump_tables.py` rebuilds `tables.go` from a firmware image. it runs the signature wrapper
under Unicorn, reads the whitebox key and the ladder constants out of the running firmware, derives
the table bases from observed reads, solves every byte permutation and blend constant by constancy
search, then validates against held-out samples it never fitted on and refuses to write anything if
validation is not exact. nothing is hardcoded.

### getting a firmware image

this repo does not decrypt anything itself - it only reads an already-decrypted image you provide.
to get one from your own device, use [wInd3x](https://github.com/freemyipod/wInd3x), the existing
public bootrom/DFU exploit tool that supports decrypting Nano 5G firmware:

```bash
./wInd3x decrypt osos5g.encrypted.osos osos5g.dec
```

supply the resulting image to `dump_tables.py`. with only a combined body, split it at `0x2e27c` -
the first part is the SRAM stub loaded at `0x22000000`, the rest is retail loaded at `0x08000000`.

## firmware support

only the last ipod nano 5G osos build. the dumper names specific function addresses
(`0x0837b814`, `0x08372998`, `0x0836749c`, the `0x08680000`-`0x086a0000` table region) and they are
that build's addresses. another firmware version needs them relocated; the dumper fails loudly
rather than producing wrong tables if the image does not match.

not tested against any other ipod model, and the `.p7b` verification path the firmware carries is
dormant on this one - itunes never creates those files.

## tests

```bash
go test ./...
```

committed tests use a synthetic guid with locally generated vectors, plus structural checks: the iv
is deterministic and digest-independent, and the signature decrypts back to `digest || rnd` under the
public key.

the stronger check - reproducing four pairs made by code that never saw this implementation, two
from apple's own itunes on a real nano 5G, one from MusicBee's `hash72.dll`, one from
ihash.marcan.st - needs a real device's guid (ihash.marcan.st only needs that to produce its pair;
itunes and MusicBee's pairs have to be captured separately), so it is not committed. set
`HASH72_VECTORS` to a json file of `{name, guid, rnd, iv}` entries and the test verifies all four
byte for byte; without it the test skips.

## what is not shipped

no firmware image, and no bytes copied from one. `tables.go` (the whitebox tables, the whitebox key,
the ladder constants) is generated locally from an image you supply and gitignored - it is a build
output, like the binary. the third-party signature pairs stay out entirely and are reached through
`HASH72_VECTORS`. the only key written out in source is `pubKey`, the published libgpod constant.

## validation

a signature from this tool was written to a real nano 5G that had no signature at all - the cbk had
been deleted and the device showed an empty library. after the write it showed its library normally
and left the file byte-identical. apple's own verifier code, run offline under an emulator, accepts
it and rejects signatures built with arbitrary ivs.

## license

mit - see [LICENSE](LICENSE)

ipod, itunes and apple are trademarks of apple inc. this is unrelated to and not endorsed by them,
and the names are used here only to say what the software is about.
