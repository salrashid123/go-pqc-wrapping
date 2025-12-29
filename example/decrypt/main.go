package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	pqcwrap "github.com/salrashid123/go-pqc-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	privateKey    = flag.String("privateKey", "certs/bare-seed-768.pem", "PrivateKey Key (bare seed only)")
	encryptedBlob = flag.String("encryptedBlob", "/tmp/encrypted.json", "Encrypted Blob")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	privatePEMBytes, err := os.ReadFile(*privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key %v\n", err)
		os.Exit(1)
	}
	wrapper := pqcwrap.NewWrapper()

	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(string(privatePEMBytes)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
	}

	b, err := os.ReadFile(*encryptedBlob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted file %v\n", err)
		os.Exit(1)
	}

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error unmarshalling %v\n", err)
		os.Exit(1)
	}

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decrypting %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Decrypted %s\n", string(plaintext))

}
