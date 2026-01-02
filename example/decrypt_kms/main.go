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
	kmsURI        = flag.String("kmsURI", "gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1", "PrivateKey Key on KMS")
	encryptedBlob = flag.String("encryptedBlob", "/tmp/encrypted.json", "Encrypted Blob")
)

func main() {
	flag.Parse()

	ctx := context.Background()

	wrapper := pqcwrap.NewWrapper()
	_, err := wrapper.SetConfig(ctx,
		pqcwrap.WithPrivateKey(*kmsURI),
		pqcwrap.WithKMSKey(true))
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

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted %s\n", string(plaintext))

}
