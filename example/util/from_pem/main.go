package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

const ()

var (
	publicKey  = flag.String("publicKey", "certs/pub-ml-kem-768-bare-seed.pem", "PublicKey")
	privateKey = flag.String("privateKey", "certs/bare-seed-768.pem", "PrivateKey")
)

const ()

var (
	mlkem512_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	mlkem768_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	mlkem1024_OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

type pkixPrivKey struct {
	Version    int `asn1:"version:0"`
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey asn1.RawContent
}

type pkixPubKey struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func main() {
	flag.Parse()

	pubPEMBytes, err := os.ReadFile(*publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key %v\n", err)
		os.Exit(1)
	}

	// acquire the ML-kem public key in PEM format
	pubPEMblock, rest := pem.Decode(pubPEMBytes)
	if len(rest) != 0 {
		fmt.Printf("error getting publicKey PEM: %v", err)
		os.Exit(1)
	}
	var pkix pkixPubKey
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		fmt.Printf("error unmarshaling publicKey PEM to asn1: %v", err)
		os.Exit(1)
	} else if len(rest) != 0 {
		fmt.Printf("error unmarshaling public PEM; rest not null")
		os.Exit(1)
	}

	var kemSharedSecret []byte
	var kemCipherText []byte
	switch pkix.Algorithm.Algorithm.String() {
	case mlkem768_OID.String():
		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			fmt.Printf("error creating encapsulation key %v", err)
			os.Exit(1)
		}
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	case mlkem1024_OID.String():
		ek, err := mlkem.NewEncapsulationKey1024(pkix.PublicKey.Bytes)
		if err != nil {
			fmt.Printf("error creating encapsulation key %v", err)
			os.Exit(1)
		}
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	default:
		fmt.Printf("error unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
		os.Exit(1)
	}

	fmt.Printf("SharedSecret %s\n", base64.StdEncoding.EncodeToString(kemSharedSecret))
	fmt.Println()
	fmt.Printf("kemSharedSecret %s\n", base64.StdEncoding.EncodeToString(kemCipherText))

	////  DECRYPT

	privPEMBytes, err := os.ReadFile(*privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key %v\n", err)
		os.Exit(1)
	}

	privPEMblock, rest := pem.Decode(privPEMBytes)
	if len(rest) != 0 {
		fmt.Printf("error getting publicKey PEM: %v", err)
		os.Exit(1)
	}
	var ppkix pkixPrivKey
	if rest, err := asn1.Unmarshal(privPEMblock.Bytes, &ppkix); err != nil {
		fmt.Printf("error unmarshaling privateKey PEM to asn1: %v", err)
		os.Exit(1)
	} else if len(rest) != 0 {
		fmt.Printf("error unmarshaling privateKey PEM; rest not null")
		os.Exit(1)
	}

	fmt.Println()

	switch pkix.Algorithm.Algorithm.String() {
	case mlkem768_OID.String():
		dk, err := mlkem.NewDecapsulationKey768(ppkix.PrivateKey)
		if err != nil {
			fmt.Printf("error creating encapsulation key %v", err)
			os.Exit(1)
		}
		sharedKey, err := dk.Decapsulate(kemCipherText)
		if err != nil {
			fmt.Printf("error decapsulating key %v", err)
			os.Exit(1)
		}
		fmt.Printf("Decapsulated kemSharedSecret %s\n", base64.StdEncoding.EncodeToString(sharedKey))
	case mlkem1024_OID.String():
		dk, err := mlkem.NewDecapsulationKey1024(ppkix.PrivateKey)
		if err != nil {
			fmt.Printf("error creating decapsulating key %v", err)
			os.Exit(1)
		}
		sharedKey, err := dk.Decapsulate(kemCipherText)
		if err != nil {
			fmt.Printf("error decapsulating key %v", err)
			os.Exit(1)
		}
		fmt.Printf("Decapsulated kemSharedSecret %s\n", base64.StdEncoding.EncodeToString(sharedKey))
	default:
		fmt.Printf("error unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
		os.Exit(1)
	}
}
