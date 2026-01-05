package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	pqcwrap "github.com/salrashid123/go-pqc-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	mode = flag.String("mode", "encrypt", "operation mode: encrypt or decrypt")

	dataToEncrypt = flag.String("dataToEncrypt", "", "data to encrypt")
	aad           = flag.String("aad", "", "with additional data")
	clientData    = flag.String("clientData", "", "JSON to include as clientdata")
	debug         = flag.Bool("debug", false, "verbose output")
	version       = flag.Bool("version", false, "print version")

	key = flag.String("key", "", "Public key to encrypt or private key to decrypt")
	in  = flag.String("in", "", "File to read encrypted data from")
	out = flag.String("out", "", "File to write encrypted data to")

	keyName           = flag.String("keyName", "", "Optional KeyName")
	Commit, Tag, Date string
)

func main() {

	flag.Parse()

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	ctx := context.Background()

	if *mode != "encrypt" && *mode != "decrypt" {
		fmt.Fprintf(os.Stderr, "Error mode must be either encrypt or decrypt\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	u, err := url.Parse(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing URL; must be one of file:// or gcpkms:// : %v\n", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	var keyBytes []byte

	useKMS := false
	switch u.Scheme {
	case "file":
		keyBytes, err = os.ReadFile(u.Path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading key file %v  \n", err)
			flag.PrintDefaults()
			os.Exit(1)
		}
	case "gcpkms":
		useKMS = true
		// todo parse and validate the kms uri://
	default:
		fmt.Fprintf(os.Stderr, "error parsing URL; must be one of file:// or gcpkms:// : %v\n", err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *mode == "encrypt" {

		wrapper := pqcwrap.NewWrapper()
		_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(keyBytes)), pqcwrap.WithClientData(*clientData), pqcwrap.WithDebug(*debug))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
			os.Exit(1)
		}

		blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad([]byte(*aad)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting %v\n", err)
			os.Exit(1)
		}

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

		err = os.WriteFile(*out, b, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing encrypted blob %v\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("Encrypted Blob: %s\n", prettyJSON.String())
			fmt.Printf("wrote encrypted blob: %s\n", *out)
		}

	} else {

		wrapper := pqcwrap.NewWrapper()
		if useKMS {
			_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(*key), pqcwrap.WithKMSKey(true), pqcwrap.WithClientData(*clientData), pqcwrap.WithDebug(*debug))
		} else {
			_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(string(keyBytes)), pqcwrap.WithClientData(*clientData), pqcwrap.WithDebug(*debug))
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating wrapper %v\n", err)
			os.Exit(1)
		}

		b, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading encrypted file %v\n", err)
			os.Exit(1)
		}

		newBlobInfo := &wrapping.BlobInfo{}
		err = protojson.Unmarshal(b, newBlobInfo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading marshalled blob %v\n", err)
			os.Exit(1)
		}

		plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad([]byte(*aad)))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting %v\n", err)
			os.Exit(1)
		}
		if *debug {
			fmt.Printf("%s", string(plaintext))
		}

		err = os.WriteFile(*out, plaintext, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing decrypted file %v\n", err)
			os.Exit(1)
		}
	}

}
