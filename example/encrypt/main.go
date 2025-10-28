package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	pqcwrap "github.com/salrashid123/go-pqc-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

const ()

var (
	publicKey     = flag.String("publicKey", "certs/pub-ml-kem-768.pem", "Public Key")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "data to encrypt")
	encryptedBlob = flag.String("encryptedBlob", "/tmp/encrypted.json", "Encrypted Blob")
)

const ()

func main() {
	flag.Parse()

	ctx := context.Background()

	pubPEMBytes, err := os.ReadFile(*publicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading public key %v\n", err)
		os.Exit(1)
	}
	wrapper := pqcwrap.NewWrapper()
	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(pubPEMBytes)), pqcwrap.WithKeyName("myname"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
		os.Exit(1)
	}

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Encrypted: %s\n", base64.StdEncoding.EncodeToString(blobInfo.Ciphertext))

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling bytes %v\n", err)
		os.Exit(1)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshalling json %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Marshalled encryptedBlob: %s\n", prettyJSON.String())

	err = os.WriteFile(*encryptedBlob, b, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing encrypted blob %v\n", err)
		os.Exit(1)
	}

}
