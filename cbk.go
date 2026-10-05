package main

import (
	"crypto/sha1"
)

const cbkBlockSize = 1024

// blockHashes is the sha1 of every 1024-byte block, the last one may be short.
func blockHashes(data []byte) []byte {
	list := make([]byte, 0, (len(data)/cbkBlockSize+1)*sha1.Size)
	for off := 0; off < len(data); off += cbkBlockSize {
		end := off + cbkBlockSize
		if end > len(data) {
			end = len(data)
		}
		sum := sha1.Sum(data[off:end])
		list = append(list, sum[:]...)
	}
	return list
}

// BuildCBK builds Locations.itdb.cbk: the signature, the sha1 it signs, then the per-block list.
// The signed sha1 is the sha1 of that list.
func BuildCBK(guid8, locations, rnd12 []byte) []byte {
	list := blockHashes(locations)
	digest := sha1.Sum(list)
	sig := Sign(guid8, digest[:], rnd12)
	out := make([]byte, 0, len(sig)+sha1.Size+len(list))
	out = append(out, sig...)
	out = append(out, digest[:]...)
	return append(out, list...)
}
