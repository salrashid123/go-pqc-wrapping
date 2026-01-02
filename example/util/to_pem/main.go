package main

import (
	"crypto/mlkem"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

const ()

var (
	private = flag.String("private", "/tmp/private.pem", "PrivateKey")
	public  = flag.String("public", "/tmp/public.pem", "PublicKey")
	keyType = flag.String("keyType", "mlkem780", "KeyType must be mlkem780 or mlkem1024")
)

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

	var privteKeyBytes []byte
	var publicKeyBytes []byte
	switch *keyType {
	case "mlkem768":

		// generate key
		nk, err := mlkem.GenerateKey768()
		if err != nil {
			fmt.Printf("error creating encapsulation key %v", err)
			os.Exit(1)
		}
		privateKey := pkixPrivKey{
			Version: 0,
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: mlkem768_OID,
			},
			PrivateKey: nk.Bytes(),
		}
		pkb, err := asn1.Marshal(privateKey)
		if err != nil {
			fmt.Printf("error marshalling key %v", err)
			os.Exit(1)
		}
		privateKeyBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkb,
		}
		privteKeyBytes = pem.EncodeToMemory(privateKeyBlock)

		// encode public key

		nk.EncapsulationKey().Bytes()
		publicKey := pkixPubKey{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: mlkem768_OID,
			},
			PublicKey: asn1.BitString{
				BitLength: len(nk.EncapsulationKey().Bytes()),
				Bytes:     nk.EncapsulationKey().Bytes(),
			},
		}
		ppkb, err := asn1.Marshal(publicKey)
		if err != nil {
			fmt.Printf("error marshalling key %v", err)
			os.Exit(1)
		}
		publicKeyBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ppkb,
		}
		publicKeyBytes = pem.EncodeToMemory(publicKeyBlock)

		//fmt.Printf("raw private key %s\n", hex.EncodeToString(nk.Bytes()))
		//fmt.Printf("raw public key %s\n", hex.EncodeToString(nk.EncapsulationKey().Bytes()))
	case "mlkem1024":
		// generate key
		nk, err := mlkem.GenerateKey1024()
		if err != nil {
			fmt.Printf("error creating encapsulation key %v", err)
			os.Exit(1)
		}
		privateKey := pkixPrivKey{
			Version: 0,
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: mlkem1024_OID,
			},
			PrivateKey: nk.Bytes(),
		}
		pkb, err := asn1.Marshal(privateKey)
		if err != nil {
			fmt.Printf("error marshalling key %v", err)
			os.Exit(1)
		}
		privateKeyBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkb,
		}
		privteKeyBytes = pem.EncodeToMemory(privateKeyBlock)

		// encode public key

		nk.EncapsulationKey().Bytes()
		publicKey := pkixPubKey{
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: mlkem1024_OID,
			},
			PublicKey: asn1.BitString{
				BitLength: len(nk.EncapsulationKey().Bytes()),
				Bytes:     nk.EncapsulationKey().Bytes(),
			},
		}
		ppkb, err := asn1.Marshal(publicKey)
		if err != nil {
			fmt.Printf("error marshalling key %v", err)
			os.Exit(1)
		}
		publicKeyBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: ppkb,
		}
		publicKeyBytes = pem.EncodeToMemory(publicKeyBlock)
	default:
		fmt.Printf("error unsupported algorithm %s", *keyType)
		os.Exit(1)
	}

	err := os.WriteFile(*private, privteKeyBytes, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing private key to file %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(*public, publicKeyBytes, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key to file %v\n", err)
		os.Exit(1)
	}

}
