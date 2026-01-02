package main

import (
	"context"
	"crypto/sha256"
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
	privateKey         = flag.String("privateKey", "certs/bare-seed-768.pem", "PrivateKey Key (bare seed only)")
	encryptedBlob      = flag.String("encryptedBlob", "/tmp/encrypted.json", "Encrypted Blob")
	aad                = flag.String("aad", "66bec62f7d14771501d8b2a66add677a5637f4eaebbd5a3b61dc9ab7988ef180", "Additional data")
	expectedClientData = flag.String("clientData", "{\"provider\": \"pqc\", \"location\": { \"zone\": \"central\",\"region\": \"us\"}}", "JSON to include as clientdata")
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

	jsonBytes, err := json.Marshal(newBlobInfo.ClientData.AsMap())
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	hasher := sha256.New()
	hasher.Write(jsonBytes)
	hashBytes := hasher.Sum(nil)

	fmt.Printf("Canonical Hash of client_data from encryptedBlob  %s\n", hex.EncodeToString(hashBytes))

	// expected clientHash

	var dataMap map[string]interface{}
	err = json.Unmarshal([]byte(*expectedClientData), &dataMap)
	if err != nil {
		log.Fatal(err)
	}
	protoStruct, err := structpb.NewStruct(dataMap)
	if err != nil {
		log.Fatal(err)
	}

	ejsonBytes, err := json.Marshal(protoStruct.AsMap())
	if err != nil {
		log.Fatalf("failed to marshal to JSON: %v", err)
	}
	ehasher := sha256.New()
	ehasher.Write(ejsonBytes)
	ehashBytes := ehasher.Sum(nil)

	fmt.Printf("Expected Canonical Hash of client_data as parameter: %s\n", hex.EncodeToString(ehashBytes))

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad(ehashBytes), pqcwrap.WithClientData(*expectedClientData))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Decrypted %s\n", string(plaintext))

	b, err = hex.DecodeString(*aad)
	if err != nil {
		log.Fatal(err)
	}
	_, err = wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad(b), pqcwrap.WithClientData(*expectedClientData))
	if err != nil {
		log.Fatal(err)
	}
}
