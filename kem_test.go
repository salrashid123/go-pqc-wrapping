package pqcwrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	kmsPrivateKey = "gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1"
	kmsPublicKey  = "example/certs/pub-ml-kem-768-kms.pem"

	bareSeedPublicPEM768  = "example/certs/pub-ml-kem-768-bare-seed.pem"
	bareSeedPrivatePEM768 = "example/certs/bare-seed-768.pem"

	seedPrivPrivatePEM768 = "example/certs/seed-only-768.pem"
)

func TestEncryptDecrypt768(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privBytes, err := os.ReadFile(bareSeedPrivatePEM768)
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

	pubBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privBytes, err := os.ReadFile(seedPrivPrivatePEM768)
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

func TestEncryptDecryptKMS768(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile(kmsPublicKey)
	require.NoError(t, err)

	keyName := "bar"

	saJSON := os.Getenv("CICD_SA_JSON")

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "cert.json")

	err = os.WriteFile(filePath, []byte(saJSON), 0644)
	require.NoError(t, err)

	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filePath)

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
	_, err = wrapperD.SetConfig(ctx, WithPrivateKey(kmsPrivateKey), WithKMSKey(true))
	require.NoError(t, err)

	plaintext, err := wrapperD.Decrypt(ctx, newBlobInfo)
	require.NoError(t, err)

	require.Equal(t, keyName, newBlobInfo.KeyInfo.KeyId)

	require.Equal(t, dataToSeal, plaintext)
}

func TestAAD(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privBytes, err := os.ReadFile(bareSeedPrivatePEM768)
	require.NoError(t, err)

	keyName := "bar"

	tests := []struct {
		name          string
		aadEncrypt    []byte
		aadDecrypt    []byte
		shouldSucceed bool
	}{
		{"aadSucceed", []byte("myaad"), []byte("myaad"), true},
		{"aadFail", []byte("myaad"), []byte("bar"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithPublicKey(string(pubBytes)), WithKeyName(keyName))
			require.NoError(t, err)

			dataToSeal := []byte("foo")

			blobInfo, err := wrapper.Encrypt(ctx, dataToSeal, wrapping.WithAad(tc.aadEncrypt))
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

			_, err = wrapperD.Decrypt(ctx, newBlobInfo, wrapping.WithAad(tc.aadDecrypt))
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}

		})
	}

}

func TestClientDataGlobal(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privBytes, err := os.ReadFile(bareSeedPrivatePEM768)
	require.NoError(t, err)

	keyName := "bar"

	tests := []struct {
		name              string
		clientDataEncrypt string
		clientDataDecrypt string

		shouldSucceed bool
	}{
		{"ClientDataGlobalSucceed", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider1\"}", true},
		{"ClientDataGlobalFail", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider2\"}", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithPublicKey(string(pubBytes)), WithKeyName(keyName), WithClientData(tc.clientDataEncrypt))
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
			_, err = wrapperD.SetConfig(ctx, WithPrivateKey(string(privBytes)), WithClientData(tc.clientDataDecrypt))
			require.NoError(t, err)

			_, err = wrapperD.Decrypt(ctx, newBlobInfo)
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}

}

func TestClientDataLocal(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privBytes, err := os.ReadFile(bareSeedPrivatePEM768)
	require.NoError(t, err)

	keyName := "bar"

	tests := []struct {
		name              string
		clientDataEncrypt string
		clientDataDecrypt string

		shouldSucceed bool
	}{
		{"ClientDataGlobalSucceed", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider1\"}", true},
		{"ClientDataGlobalFail", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider2\"}", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithPublicKey(string(pubBytes)), WithKeyName(keyName))
			require.NoError(t, err)

			dataToSeal := []byte("foo")

			blobInfo, err := wrapper.Encrypt(ctx, dataToSeal, WithClientData(tc.clientDataEncrypt))
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

			_, err = wrapperD.Decrypt(ctx, newBlobInfo, WithClientData(tc.clientDataDecrypt))
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestClientDataMix(t *testing.T) {

	ctx := context.Background()

	pubBytes, err := os.ReadFile(bareSeedPublicPEM768)
	require.NoError(t, err)

	privBytes, err := os.ReadFile(bareSeedPrivatePEM768)
	require.NoError(t, err)

	keyName := "bar"

	tests := []struct {
		name              string
		clientDataEncrypt string
		clientDataDecrypt string

		shouldSucceed bool
	}{
		{"ClientDataGlobalSucceed", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider1\"}", true},
		{"ClientDataGlobalFail", "{\"provider\": \"provider1\"}", "{\"provider\": \"provider2\"}", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			wrapper := NewWrapper()
			_, err = wrapper.SetConfig(ctx, WithPublicKey(string(pubBytes)), WithKeyName(keyName), WithClientData(tc.clientDataEncrypt))
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

			_, err = wrapperD.Decrypt(ctx, newBlobInfo, WithClientData(tc.clientDataDecrypt))
			if tc.shouldSucceed {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
