package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	pqcwrap "github.com/salrashid123/go-pqc-wrapping"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const ()

var (
	publicKey     = flag.String("publicKey", "certs/pub-ml-kem-768-bare-seed.pem", "Public Key")
	dataToEncrypt = flag.String("dataToEncrypt", "foo", "data to encrypt")
	encryptedBlob = flag.String("encryptedBlob", "/tmp/encrypted.json", "Encrypted Blob")
	clientData    = flag.String("clientData", "{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}", "JSON to include as clientdata")
)

const ()

func main() {
	flag.Parse()

	ctx := context.Background()

	pubPEMBytes, err := os.ReadFile(*publicKey)
	if err != nil {
		log.Fatal(err)
	}
	wrapper := pqcwrap.NewWrapper()

	var dataMap map[string]interface{}
	err = json.Unmarshal([]byte(*clientData), &dataMap)
	if err != nil {
		log.Fatal(err)
	}
	protoStruct, err := structpb.NewStruct(dataMap)
	if err != nil {
		log.Fatal(err)
	}

	jsonBytes, err := json.Marshal(protoStruct.AsMap())
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(jsonBytes)
	hashBytes := hasher.Sum(nil)

	fmt.Printf("Canonical Hash: %s\n", hex.EncodeToString(hashBytes))

	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(pubPEMBytes)),
		pqcwrap.WithKeyName("myname"),
		pqcwrap.WithClientData(*clientData))
	if err != nil {
		log.Fatal(err)
	}
	// use the hash of the client data as the aad
	// note you can embed the actual aad string as part of the client_data and then hash it if you want

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad(hashBytes))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted: %s\n", base64.StdEncoding.EncodeToString(blobInfo.Ciphertext))

	b, err := protojson.Marshal(blobInfo)
	if err != nil {
		log.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Marshalled encryptedBlob: %s\n", prettyJSON.String())

	err = os.WriteFile(*encryptedBlob, b, 0666)
	if err != nil {
		log.Fatal(err)
	}

}
