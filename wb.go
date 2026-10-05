package main

// wbCipher is the fixed-key whitebox aes the firmware runs. tables come from tables.go.
func wbCipher(pt []byte) []byte {
	in := make([]byte, 16)
	for i := 0; i < 16; i++ {
		in[i] = t0Input[pt[p1[i]]] ^ c1[i]
	}
	for r := 0; r < 9; r++ {
		tabs := tabsN[:]
		if r == 0 {
			tabs = k1[:]
		}
		bs := make([]byte, 16)
		for c := 0; c < 4; c++ {
			var v uint32
			for t := 0; t < 4; t++ {
				v ^= tt[tabs[4*c+t]][in[4*c+t]]
			}
			bs[4*c] = byte(v)
			bs[4*c+1] = byte(v >> 8)
			bs[4*c+2] = byte(v >> 16)
			bs[4*c+3] = byte(v >> 24)
		}
		if r == 8 {
			out := make([]byte, 16)
			for i := 0; i < 16; i++ {
				out[i] = gOut[i][bs[permLast[i]]^k9[i]]
			}
			return out
		}
		for j := 0; j < 16; j++ {
			in[j] = bs[permMid[j]] ^ ks[r][j]
		}
	}
	return nil
}
