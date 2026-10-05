package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
)

func main() {
	rndFlag := flag.String("rnd", "", "fixed rnd12 as 24 hex chars (default: random)")
	digest := flag.String("digest", "", "20-byte digest as 40 hex chars, for signing a known SHA1")
	itdb := flag.String("itdb", "", "path to Locations.itdb; the digest is computed from it")
	out := flag.String("out", "", "write the full .cbk here (needs -itdb)")
	uuid := flag.Bool("uuid", false, "also print a libgpod-style HashInfo (uuid20 || rnd12 || iv16)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: hash72 [-rnd HEX24] [-digest HEX40] [-itdb FILE] [-out FILE] [-uuid] GUID16")
		fmt.Fprintln(os.Stderr, "       GUID16 is the 16-char Firewire ID as hex, e.g. 0102030405060708")
		fmt.Fprintln(os.Stderr, "       with no -digest and no -itdb this prints just the (rnd, iv) pair")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	guid, err := decodeHex(flag.Arg(0))
	if err != nil || len(guid) != 8 {
		fmt.Fprintln(os.Stderr, "guid must be 16 hex chars")
		os.Exit(2)
	}

	var rnd []byte
	if *rndFlag != "" {
		rnd, err = decodeHex(*rndFlag)
		if err != nil || len(rnd) != 12 {
			fmt.Fprintln(os.Stderr, "-rnd must be 24 hex chars")
			os.Exit(2)
		}
	} else {
		rnd = make([]byte, 12)
		if _, err := rand.Read(rnd); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	iv := IV(guid, rnd)
	fmt.Printf("guid  %x\n", guid)
	fmt.Printf("rnd   %x\n", rnd)
	fmt.Printf("iv    %x\n", iv)

	if *uuid {
		id20 := append(append([]byte{}, guid...), make([]byte, 12)...)
		fmt.Printf("hashinfo %x\n", append(append(id20, rnd...), iv...))
	}

	if *itdb != "" {
		data, err := os.ReadFile(*itdb)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(data) == 0 {
			fmt.Fprintln(os.Stderr, "itdb is empty")
			os.Exit(2)
		}
		cbk := BuildCBK(guid, data, rnd)
		fmt.Printf("digest    %x\n", cbk[46:66])
		fmt.Printf("signature %x\n", cbk[:46])
		if *out != "" {
			if err := os.WriteFile(*out, cbk, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Printf("wrote %s (%d bytes)\n", *out, len(cbk))
		}
		return
	}

	if *digest != "" {
		dg, err := decodeHex(*digest)
		if err != nil || len(dg) != 20 {
			fmt.Fprintln(os.Stderr, "-digest must be 40 hex chars")
			os.Exit(2)
		}
		fmt.Printf("signature %x\n", Sign(guid, dg, rnd))
	}
}
