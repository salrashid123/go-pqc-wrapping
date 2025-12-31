package pqcwrap

import (
	"crypto/mlkem"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"
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
	kmsKey       bool
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
	s.publicKey = opts.withPublicKey
	s.privateKey = opts.withPrivateKey
	s.keyName = opts.withKeyName
	s.kmsKey = opts.withKMSKey
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

// Encrypts data using a the KEM sharedKey
func (s *PQCWrapper) Encrypt(ctx context.Context, plaintext []byte, opt ...wrapping.Option) (*wrapping.BlobInfo, error) {
	if plaintext == nil {
		return nil, errors.New("given plaintext for encryption is nil")
	}

	// acquire the ML-kem public key in PEM format
	pubPEMblock, rest := pem.Decode([]byte(s.publicKey))
	if len(rest) != 0 {
		return nil, fmt.Errorf("error getting publicKey PEM")
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

	// initialize an encapsulation key based on the type
	// then acquire the kem ciphertext and the sharedkey
	var keyType pqcwrappb.Secret_KeyType
	switch pkix.Algorithm.Algorithm.String() {
	case mlkem780_OID.String():
		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error creating encapsulation key %v", err)
		}
		keyType = pqcwrappb.Secret_ml_kem_768
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	case mlkem1024_OID.String():
		ek, err := mlkem.NewEncapsulationKey1024(pkix.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error creating encapsulation key %v", err)
		}
		keyType = pqcwrappb.Secret_ml_kem_1024
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	default:
		return nil, fmt.Errorf("error unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
	}

	w := wrapaead.NewWrapper()
	_, err := w.SetConfig(ctx, opt...)
	if err != nil {
		return nil, fmt.Errorf("error setting config %v", err)
	}
	err = w.SetAesGcmKeyBytes(kemSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("error setting AESGCM Key %v", err)
	}
	c, err := w.Encrypt(ctx, plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("error encrypting %v", err)
	}

	wrappb := &pqcwrappb.Secret{
		Name:          s.keyName,
		Version:       KeyVersion,
		Type:          keyType,
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
		Ciphertext: c.Ciphertext,
		Iv:         c.Iv,
		Hmac:       c.Hmac,
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

	var sharedKey []byte
	if s.kmsKey {
		kmsName := ""
		if strings.HasPrefix(s.privateKey, "gcpkms://") {
			kmsName = strings.TrimPrefix(s.privateKey, "gcpkms://")
		} else {
			return nil, fmt.Errorf("unsupported kms prefix %s", s.privateKey)
		}
		ctx := context.Background()
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, err
		}
		defer client.Close()

		resp, err := client.Decapsulate(ctx, &kmspb.DecapsulateRequest{
			Name:       kmsName,
			Ciphertext: wrappb.KemCipherText,
		})
		if err != nil {
			return nil, err
		}
		sharedKey = resp.SharedSecret

	} else {
		// extract the private ML-KEM key
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

		// now create a decapsulationKey based on the declared type
		//  then acquire the raw (decrypted) sharedKey
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

	}

	w := wrapaead.NewWrapper()
	_, err = w.SetConfig(ctx, opt...)
	if err != nil {
		return nil, fmt.Errorf("error setting config %v", err)
	}
	err = w.SetAesGcmKeyBytes(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("error setting AESGCM Key %v", err)
	}
	d, err := w.Decrypt(ctx, in, opt...)
	if err != nil {
		return nil, fmt.Errorf("error decrypting %v", err)
	}

	return d, nil
}
