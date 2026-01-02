package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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
		log.Fatal(err)
	}
	wrapper := pqcwrap.NewWrapper()

	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(string(privatePEMBytes)))
	if err != nil {
		log.Fatal(err)
	}

	b, err := os.ReadFile(*encryptedBlob)
	if err != nil {
		log.Fatal(err)
	}

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	if err != nil {
		log.Fatal(err)
	}

	aad := []byte("myaad")

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad(aad))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted %s\n", string(plaintext))

}
