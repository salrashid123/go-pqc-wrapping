package pqcwrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/salrashid123/go-pqc-wrapping/pqcwrappb"
	context "golang.org/x/net/context"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	WrapperTypePQC wrapping.WrapperType = "pqc"
)

// Configures and manages the PQC encryption wrapper
//
//	Values here are set using setConfig or options
type PQCWrapper struct {
	currentKeyId *atomic.Value
	keyName      string
	publicKey    string
	privateKey   string
	debug        bool
	userAgent    string
}

var (
	_ wrapping.Wrapper = (*PQCWrapper)(nil)
)

// Initialize a TPM based encryption wrapper
func NewWrapper() *PQCWrapper {

	s := &PQCWrapper{
		currentKeyId: new(atomic.Value),
	}
	s.currentKeyId.Store("")
	return s
}

// Set the configuration options
func (s *PQCWrapper) SetConfig(_ context.Context, opt ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, err
	}

	s.userAgent = opts.withUserAgent
	switch {
	case os.Getenv(EnvPublicKey) != "" && !opts.Options.WithDisallowEnvVars:
		s.publicKey = os.Getenv(EnvPublicKey)
	case opts.withPublicKey != "":
		s.publicKey = opts.withPublicKey
	}

	switch {
	case os.Getenv(EnvPrivateKey) != "" && !opts.Options.WithDisallowEnvVars:
		s.privateKey = os.Getenv(EnvPrivateKey)
	case opts.withPrivateKey != "":
		s.privateKey = opts.withPrivateKey
	}
	switch {
	case os.Getenv(EnvKeyName) != "" && !opts.Options.WithDisallowEnvVars:
		s.keyName = os.Getenv(EnvKeyName)
	case opts.withKeyName != "":
		s.keyName = opts.withKeyName
	}

	s.debug = opts.withDebug

	// Map that holds non-sensitive configuration info to return
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata[KeyName] = s.keyName
	wrapConfig.Metadata[PublicKey] = s.publicKey
	//wrapConfig.Metadata[PrivateKey] = s.privateKey

	return wrapConfig, nil
}

func (s *PQCWrapper) Type(_ context.Context) (wrapping.WrapperType, error) {
	return WrapperTypePQC, nil
}

func (s *PQCWrapper) KeyId(_ context.Context) (string, error) {
	return s.currentKeyId.Load().(string), nil
}

// Encrypts data using a TPM's Storage Root Key (SRK)
func (s *PQCWrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error wrapping data: %w", err)
	}

	pubPEMblock, rest := pem.Decode([]byte(s.publicKey))
	if len(rest) != 0 {
		return nil, fmt.Errorf("error getting publicKey PEM: %w", err)
	}
	var pkix pkixPubKey
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		return nil, fmt.Errorf("error unmarshaling public PEM to asn1: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("error unmarshaling publicKey PEM; rest not null")
	}

	var kemCipherText []byte
	var kemSharedSecret []byte
	var wrappedCipherText []byte

	switch pkix.Algorithm.Algorithm.String() {
	case mlkem780_OID.String():
		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error creating encapsulation key %v", err)
		}
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	case mlkem1024_OID.String():
		ek, err := mlkem.NewEncapsulationKey1024(pkix.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error creating encapsulation key %v", err)
		}
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	default:
		return nil, fmt.Errorf("error unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
	}

	block, err := aes.NewCipher(kemSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("error creating aes inner cipher %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating AES GCM %v", err)
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error creating aes nonce %v", err)
	}

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options %v", err)
	}

	wrappedCipherText = aesgcm.Seal(nil, nonce, env.Key, opts.GetWithAad())
	wrappedCipherText = append(nonce, wrappedCipherText...)

	wrappb := &pqcwrappb.Secret{
		Name:          s.keyName,
		Version:       KeyVersion,
		Type:          pqcwrappb.Secret_ml_kem_768,
		KemCipherText: kemCipherText,
		WrappedRawKey: wrappedCipherText,
	}

	// get the bytes of the proto
	b, err := protojson.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap proto Key: %v", err)
	}

	// Store current key id value
	s.currentKeyId.Store(s.keyName)

	ret := &wrapping.BlobInfo{
		Ciphertext: env.Ciphertext,
		Iv:         env.Iv,
		KeyInfo: &wrapping.KeyInfo{
			KeyId:      s.keyName,
			WrappedKey: b,
		},
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (s *PQCWrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in.Ciphertext == nil {
		return nil, fmt.Errorf("given ciphertext for decryption is nil")
	}

	wrappb := &pqcwrappb.Secret{}
	err := protojson.Unmarshal(in.KeyInfo.WrappedKey, wrappb)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap proto Key: %v", err)
	}

	prPEMblock, rest := pem.Decode([]byte(s.privateKey))
	if len(rest) != 0 {
		return nil, fmt.Errorf("error getting private PEM: %w", err)
	}

	var prkix pkixPrivKey
	if rest, err := asn1.Unmarshal(prPEMblock.Bytes, &prkix); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key")
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("failed to decode private key PEM rest")
	}

	var sharedKey []byte

	switch prkix.Algorithm.Algorithm.String() {
	case mlkem780_OID.String():
		dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("error reading mlkem private PEM: %w", err)
		}

		sharedKey, err = dk.Decapsulate(wrappb.KemCipherText)
		if err != nil {
			return nil, fmt.Errorf("error decapsulating: %w", err)
		}
	case mlkem1024_OID.String():
		dk, err := mlkem.NewDecapsulationKey1024(prkix.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("error reading mlkem private PEM: %w", err)
		}

		sharedKey, err = dk.Decapsulate(wrappb.KemCipherText)
		if err != nil {
			return nil, fmt.Errorf("error decapsulating: %w", err)
		}
	default:
		return nil, fmt.Errorf("error unsupported algorithm %s", prkix.Algorithm.Algorithm.String())
	}

	block, err := aes.NewCipher(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("error initializing aes cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error initialing gcm: %w", err)
	}

	nonce := wrappb.WrappedRawKey[:aesgcm.NonceSize()]
	ciphertext := wrappb.WrappedRawKey[aesgcm.NonceSize():]

	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("error reading options %v", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, opts.GetWithAad())
	if err != nil {
		return nil, fmt.Errorf("error decrypting aes gcm  cipher: %w", err)
	}

	// the unsealed data is the inner encryption key
	envInfo := &wrapping.EnvelopeInfo{
		Key:        plaintext,
		Iv:         in.Iv,
		Ciphertext: in.Ciphertext,
	}

	// we're finally ready to decrypt the ciphertext
	plaintext, err = wrapping.EnvelopeDecrypt(envInfo, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data with envelope: %w", err)
	}

	return plaintext, nil
}
