package pqcwrap

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
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
	"google.golang.org/protobuf/types/known/structpb"
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
	clientData   *structpb.Struct
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

	s.publicKey = opts.withPublicKey
	s.privateKey = opts.withPrivateKey
	s.keyName = opts.withKeyName
	s.kmsKey = opts.withKMSKey
	s.clientData = opts.withClientData
	s.debug = opts.withDebug

	if opts.WithAad != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: AAD must be specified only on Encrypt or Decrypt")
	}

	// Map that holds non-sensitive configuration info to return
	wrapConfig := new(wrapping.WrapperConfig)
	wrapConfig.Metadata = make(map[string]string)
	wrapConfig.Metadata[KeyName] = s.keyName
	wrapConfig.Metadata[PublicKey] = s.publicKey

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
		return nil, errors.New("go-pqc-wrapping: plaintext for encryption cannot be nil")
	}

	if s.publicKey == "" {
		return nil, fmt.Errorf("go-pqc-wrapping: error public key cannot be nil for encrypting")
	}
	// acquire the ML-kem public key in PEM format
	pubPEMblock, rest := pem.Decode([]byte(s.publicKey))
	if len(rest) != 0 {
		return nil, fmt.Errorf("go-pqc-wrapping: error decoding provided as PEM")
	}
	var pkix pkixPubKey
	if rest, err := asn1.Unmarshal(pubPEMblock.Bytes, &pkix); err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error unmarshaling public PEM to asn1: %w", err)
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("go-pqc-wrapping: error unmarshaling publicKey PEM; rest not null")
	}

	var kemCipherText []byte
	var kemSharedSecret []byte

	// initialize an encapsulation key based on the type
	// then acquire the kem ciphertext and the sharedkey
	var keyType pqcwrappb.Secret_KeyType
	switch pkix.Algorithm.Algorithm.String() {
	case mlkem768_OID.String():
		ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("go-pqc-wrapping: error creating encapsulation key %v", err)
		}
		keyType = pqcwrappb.Secret_ml_kem_768
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	case mlkem1024_OID.String():
		ek, err := mlkem.NewEncapsulationKey1024(pkix.PublicKey.Bytes)
		if err != nil {
			return nil, fmt.Errorf("go-pqc-wrapping: error creating encapsulation key %v", err)
		}
		keyType = pqcwrappb.Secret_ml_kem_1024
		kemSharedSecret, kemCipherText = ek.Encapsulate()
	default:
		return nil, fmt.Errorf("go-pqc-wrapping: error unsupported algorithm %s", pkix.Algorithm.Algorithm.String())
	}

	// see if global clientData was set
	//  if its also set in the Encrypt() options, use that as instead
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error parsing options %v", err)
	}
	cd := s.clientData
	if opts.withClientData != nil {
		cd = opts.withClientData
	}

	if s.debug {
		fmt.Printf("go-pqc-wrapping: using AAD: %s\n", opts.GetWithAad())
		fmt.Printf("go-pqc-wrapping: using clientData: %s\n", cd.String())
	}

	// now encrypt the plaintext using the aes-gcm key which we sealed earlier into the tpm object
	// the library we're using to do that is "github.com/hashicorp/go-kms-wrapping/v2/aead"
	//  note the ciphertext already has the iv included in it
	//  https://github.com/hashicorp/go-kms-wrapping/blob/main/aead/aead.go#L242-L249
	w := wrapaead.NewWrapper()
	err = w.SetAesGcmKeyBytes(kemSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error setting AESGCM Key %v", err)
	}
	// the opt... can include any aad you set during encrypt
	c, err := w.Encrypt(ctx, plaintext, opt...)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error encrypting using AESKey %v", err)
	}

	wrappb := &pqcwrappb.Secret{
		Name:          s.keyName,
		Version:       KeyVersion,
		Type:          keyType,
		KemCipherText: kemCipherText,
		// PublicKey:     []byte(s.publicKey),  // todo, add flag to optionally include the public key
	}

	// get the bytes of the proto
	wrappedSecretproto, err := protojson.Marshal(wrappb)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: failed to wrap proto Key: %v", err)
	}

	// Store current key id value
	s.currentKeyId.Store(s.keyName)

	ret := &wrapping.BlobInfo{
		Ciphertext: c.Ciphertext, // add the aes wrapped ciphertext into the blobinfo
		//Iv:         c.Iv,         // no need to send in any IV since its already part of the ciphertext
		//Hmac: c.Hmac,
		KeyInfo: &wrapping.KeyInfo{
			Mechanism:  uint64(keyType),
			KeyId:      s.keyName,
			WrappedKey: wrappedSecretproto,
		},
		ClientData: cd,
	}

	return ret, nil
}

// Decrypt is used to decrypt the ciphertext.
func (s *PQCWrapper) Decrypt(ctx context.Context, in *wrapping.BlobInfo, opt ...wrapping.Option) ([]byte, error) {
	if in.Ciphertext == nil {
		return nil, fmt.Errorf("go-pqc-wrapping: given ciphertext for decryption is nil")
	}

	// unmarshall the secret
	wrappb := &pqcwrappb.Secret{}
	err := protojson.Unmarshal(in.KeyInfo.WrappedKey, wrappb)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: failed to unwrap proto Key: %v", err)
	}

	// check if the versions match
	if wrappb.Version != KeyVersion {
		return nil, fmt.Errorf("go-pqc-wrapping: key is encoded by key version [%d] which is incompatile with the current version [%d]\n\nsee: https://github.com/salrashid123/go-pqc-wrapping/tree/main?tab=readme-ov-file#versions", wrappb.Version, KeyVersion)
	}

	// see if global clientData was set
	//  if its also set in the Encrypt() options, use that as instead
	cd := s.clientData
	opts, err := getOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error parsing options %v", err)
	}
	if opts.withClientData != nil {
		cd = opts.withClientData
	}

	// if a value of clientData was provided in the decryption step or in config,
	//  compare that to what was encoded into the BlobInfo
	// if they are different, bail
	if cd != nil {

		// get the hash of the value of the client_data provided in encoded file
		ejsonBytes, err := json.Marshal(in.ClientData.AsMap())
		if err != nil {
			return nil, fmt.Errorf("go-pqc-wrapping: failed to read clientData from blobinfo: %v", err)
		}
		ehasher := sha256.New()
		ehasher.Write(ejsonBytes)
		ehashBytes := ehasher.Sum(nil)

		// get the has of the value provided in the setConfig() or Decrypt() step
		providedJsonBytes, err := json.Marshal(cd.AsMap())
		if err != nil {
			return nil, fmt.Errorf("fgo-pqc-wrapping: ailed to read clientData from parameter: %v", err)
		}
		phasher := sha256.New()
		phasher.Write(providedJsonBytes)
		phashBytes := phasher.Sum(nil)

		// bail if they are different
		if !bytes.Equal(ehashBytes, phashBytes) {
			return nil, fmt.Errorf("go-pqc-wrapping: Provided client_data does not match.  \nfrom blobinfo \n[%s]\nfrom prarameter \n[%s]", in.ClientData.String(), cd.String())
		}
	}

	if s.debug {
		fmt.Printf("go-pqc-wrapping: using AAD: %s\n", opts.GetWithAad())
		fmt.Printf("go-pqc-wrapping: using clientData: %s\n", cd.String())
	}

	// decapsulate the sharedKey from the kemCipherText
	var sharedKey []byte
	if s.kmsKey {
		kmsName := ""
		if strings.HasPrefix(s.privateKey, "gcpkms://") {
			kmsName = strings.TrimPrefix(s.privateKey, "gcpkms://")
		} else {
			return nil, fmt.Errorf("go-pqc-wrapping: unsupported kms prefix %s", s.privateKey)
		}
		ctx := context.Background()
		client, err := kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("go-pqc-wrapping: error creating GCP KMS client %v", err)
		}
		defer client.Close()

		resp, err := client.Decapsulate(ctx, &kmspb.DecapsulateRequest{
			Name:       kmsName,
			Ciphertext: wrappb.KemCipherText,
		})
		if err != nil {
			return nil, fmt.Errorf("go-pqc-wrapping: error decapsulating with KMS %v", err)
		}
		sharedKey = resp.SharedSecret

	} else {
		// extract the private ML-KEM key
		prPEMblock, rest := pem.Decode([]byte(s.privateKey))
		if len(rest) != 0 {
			return nil, fmt.Errorf("go-pqc-wrapping: error getting private PEM: %w", err)
		}

		var prkix pkixPrivKey
		if rest, err := asn1.Unmarshal(prPEMblock.Bytes, &prkix); err != nil {
			return nil, fmt.Errorf("go-pqc-wrapping: failed to unmarshal private key")
		} else if len(rest) != 0 {
			return nil, fmt.Errorf("go-pqc-wrapping: failed to decode private key PEM rest")
		}

		// now create a decapsulationKey based on the declared type
		//  then acquire the raw (decrypted) sharedKey
		switch prkix.Algorithm.Algorithm.String() {
		case mlkem768_OID.String():
			dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("go-pqc-wrapping: error reading mlkem private PEM: %w", err)
			}

			sharedKey, err = dk.Decapsulate(wrappb.KemCipherText)
			if err != nil {
				return nil, fmt.Errorf("go-pqc-wrapping: error decapsulating: %w", err)
			}
		case mlkem1024_OID.String():
			dk, err := mlkem.NewDecapsulationKey1024(prkix.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("go-pqc-wrapping: error reading mlkem private PEM: %w", err)
			}

			sharedKey, err = dk.Decapsulate(wrappb.KemCipherText)
			if err != nil {
				return nil, fmt.Errorf("go-pqc-wrapping: error decapsulating: %w", err)
			}
		default:
			return nil, fmt.Errorf("go-pqc-wrapping: error unsupported algorithm %s", prkix.Algorithm.Algorithm.String())
		}

	}

	// use the sharedKey to decrypt the data
	//   the opt... you pass in includes any  AAD you set
	w := wrapaead.NewWrapper()
	err = w.SetAesGcmKeyBytes(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error setting AESGCM Key %v", err)
	}
	d, err := w.Decrypt(ctx, in, opt...)
	if err != nil {
		return nil, fmt.Errorf("go-pqc-wrapping: error decrypting %v", err)
	}

	return d, nil
}
