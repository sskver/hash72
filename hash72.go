package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"math/big"
)

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }

// the public libgpod hash72 key.
var pubKey = []byte{0x61, 0x8c, 0xa1, 0x0d, 0xc7, 0xf5, 0x7f, 0xd3,
	0xb4, 0x72, 0x3e, 0x08, 0x15, 0x74, 0x63, 0xd7}

// encByte and decByte are the firmware's byte transform and its inverse.
func encByte(x byte) byte { return byte((encA*int(x) + encB) % 256) }
func decByte(x byte) byte { return byte((decA*int(x) + decB) % 256) }

func encBuf(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = encByte(v)
	}
	return out
}

func decBuf(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = decByte(v)
	}
	return out
}

// IV derives the cbc iv from the guid and rnd12. it does not depend on the digest.
//
// the firmware runs the whitebox three times and each output gives an iv the verifier accepts.
// this is the first one, the branch itunes, MusicBee and ihash all produce.
func IV(guid8, rnd12 []byte) []byte {
	in0 := encBuf(append(append([]byte{}, guid8...), rnd12[:8]...))
	o0 := wbCipher(in0)
	v := new(big.Int).SetBytes(decBuf(o0))
	s := int(rnd12[8]) + int(rnd12[9]) + int(rnd12[10]) + int(rnd12[11])
	s %= 17
	c := ladderIV(v, 13+s)
	b := c.Bytes()
	out := make([]byte, 16)
	copy(out[16-len(b):], b)
	return out
}

// Sign returns the 46-byte hash72 signature: 01 00 || rnd12 || ct32.
func Sign(guid8, digest20, rnd12 []byte) []byte {
	block, err := aes.NewCipher(pubKey)
	if err != nil {
		panic(err)
	}
	ct := make([]byte, 32)
	cipher.NewCBCEncrypter(block, IV(guid8, rnd12)).CryptBlocks(ct, append(append([]byte{}, digest20...), rnd12...))
	out := []byte{1, 0}
	out = append(out, rnd12...)
	return append(out, ct...)
}
