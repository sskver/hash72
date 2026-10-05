package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// synthetic GUID and locally generated vectors, so the committed tests carry no real device
// identifier. regenerate with: go run . -rnd HEX24 0102030405060708
var ivVectors = []struct {
	name string
	rnd  string
	iv   string
}{
	{"all-zero rnd", "000000000000000000000000", "1096b88ff4899b7881781faa5eaad5fd"},
	{"low rnd", "00112233445566778899aabb", "447e5140f0721387928733d59fd60028"},
	{"high rnd", "deadbeefcafebabefaced000", "5124c07378d49965525737be9d764f27"},
}

func TestIV(t *testing.T) {
	guid := mustHex(t, "0102030405060708")
	for _, tc := range ivVectors {
		got := IV(guid, mustHex(t, tc.rnd))
		if want := mustHex(t, tc.iv); string(got) != string(want) {
			t.Errorf("%s: iv = %x, want %x", tc.name, got, want)
		}
	}
}

// the IV must not depend on the digest, and the signature must decrypt back to digest||rnd
// under the public key. both hold for any guid, so no device-specific data is needed.
func TestStructure(t *testing.T) {
	guid := mustHex(t, "0102030405060708")
	rnd := mustHex(t, "0123456789abcdef01234567")
	d1 := mustHex(t, "1111111111111111111111111111111111111111")
	d2 := mustHex(t, "2222222222222222222222222222222222222222")

	if string(IV(guid, rnd)) != string(IV(guid, rnd)) {
		t.Fatal("nondeterministic IV")
	}
	iv1 := IV(guid, rnd)
	iv2 := IV(guid, rnd)
	if string(iv1) != string(iv2) {
		t.Errorf("IV changed between calls")
	}

	for _, dg := range [][]byte{d1, d2} {
		sig := Sign(guid, dg, rnd)
		if len(sig) != 46 {
			t.Fatalf("signature length %d, want 46", len(sig))
		}
		if sig[0] != 1 || sig[1] != 0 {
			t.Errorf("bad header %x", sig[:2])
		}
		if string(sig[2:14]) != string(rnd) {
			t.Errorf("rnd not embedded verbatim")
		}
		ct := sig[14:]
		block, err := aes.NewCipher(pubKey)
		if err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, 32)
		cipher.NewCBCDecrypter(block, iv1).CryptBlocks(plain, ct)
		if string(plain) != string(dg)+string(rnd) {
			t.Errorf("signature does not decrypt to digest||rnd")
		}
	}
}

// third-party pairs (itunes, MusicBee, ihash.marcan.st) are the strongest external check, but they
// belong to a specific real device and are not committed. set HASH72_VECTORS to a json file of
// {name, guid, rnd, iv} entries to enable them.
func TestThirdPartyPairs(t *testing.T) {
	path := os.Getenv("HASH72_VECTORS")
	if path == "" {
		path = "thirdparty_vectors.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("no third-party vectors at " + path)
	}
	type vec struct {
		Name string `json:"name"`
		Guid string `json:"guid"`
		Rnd  string `json:"rnd"`
		IV   string `json:"iv"`
	}
	var vs []vec
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatalf("bad vectors file: %v", err)
	}
	for _, v := range vs {
		got := IV(mustHex(t, v.Guid), mustHex(t, v.Rnd))
		if want := mustHex(t, v.IV); string(got) != string(want) {
			t.Errorf("%s: iv = %x, want %x", v.Name, got, want)
		}
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}
