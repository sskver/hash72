package main

import "math/big"

// the signature ladder: a two-register recurrence over GF(N). the firmware keeps bignums as four
// little-endian limbs scaled by a constant, and writes the result big-endian with every byte
// negated. both are undone here so this returns the plain iv.
var (
	fieldN     = fromHex(ladderNHex)
	ladderM    = fromHex(ladderMHex)
	inv2pow128 = new(big.Int).ModInverse(ladderReduce, fieldN)
)

func fromHex(s string) *big.Int {
	v, _ := new(big.Int).SetString(s, 16)
	return v
}

func mont(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Mul(a, b), inv2pow128), fieldN)
}

// ladderIV runs the recurrence iters times from (A=M, C=v) and returns C.
func ladderIV(v *big.Int, iters int) *big.Int {
	a := new(big.Int).Set(ladderM)
	c := new(big.Int).Mod(v, fieldN)
	for i := 0; i < iters; i++ {
		na := mont(ladderCst, mont(a, a))
		na.Sub(na, mont(ladderCst, mont(c, c)))
		na.Add(na, ladderM)
		na.Mod(na, fieldN)

		nc := mont(ladderCst, mont(c, a))
		nc.Lsh(nc, 1)
		nc.Add(nc, c0(v))
		nc.Mod(nc, fieldN)

		a, c = na, nc
	}
	return c
}

// v is already reduced mod N at every call site, but keep it explicit.
func c0(v *big.Int) *big.Int { return new(big.Int).Mod(v, fieldN) }
