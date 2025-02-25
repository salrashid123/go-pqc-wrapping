package pqcwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestEncryptDecrypt768(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile("example/certs/pub-ml-kem-768.pem")
	require.NoError(t, err)

	privBytes, err := os.ReadFile("example/certs/bare-seed.pem")
	require.NoError(t, err)

	keyName := "bar"

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithPublicKey(string(pubBytes)), WithKeyName(keyName))
	require.NoError(t, err)

	dataToSeal := []byte("foo")

	blobInfo, err := wrapper.Encrypt(ctx, dataToSeal)
	require.NoError(t, err)

	b, err := protojson.Marshal(blobInfo)
	require.NoError(t, err)

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	require.NoError(t, err)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	require.NoError(t, err)

	wrapperD := NewWrapper()
	_, err = wrapperD.SetConfig(ctx, WithPrivateKey(string(privBytes)))
	require.NoError(t, err)

	plaintext, err := wrapperD.Decrypt(ctx, newBlobInfo)
	require.NoError(t, err)

	require.Equal(t, keyName, newBlobInfo.KeyInfo.KeyId)

	require.Equal(t, dataToSeal, plaintext)
}

func TestEncryptDecrypt768Fail(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile("example/certs/pub-ml-kem-768.pem")
	require.NoError(t, err)

	privBytes, err := os.ReadFile("example/certs/seed-only.pem")
	require.NoError(t, err)

	keyName := "bar"

	wrapper := NewWrapper()
	_, err = wrapper.SetConfig(ctx, WithPublicKey(string(pubBytes)), WithKeyName(keyName))
	require.NoError(t, err)

	dataToSeal := []byte("foo")

	blobInfo, err := wrapper.Encrypt(ctx, dataToSeal)
	require.NoError(t, err)

	b, err := protojson.Marshal(blobInfo)
	require.NoError(t, err)

	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, b, "", "\t")
	require.NoError(t, err)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)
	require.NoError(t, err)

	wrapperD := NewWrapper()
	_, err = wrapperD.SetConfig(ctx, WithPrivateKey(string(privBytes)))
	require.NoError(t, err)

	_, err = wrapperD.Decrypt(ctx, newBlobInfo)
	require.Error(t, err)

}
