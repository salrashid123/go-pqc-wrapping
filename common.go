package pqcwrap

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	mlkem512_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	mlkem780_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	mlkem1024_OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

type pkixPrivKey struct {
	Version    int `asn1:"version:0"`
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey asn1.RawContent
}

type pkixPubKey struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

const (
	EnvPublicKey  = "PQC_PUBLIC_KEY"
	EnvPrivateKey = "PQC_PRIVATE_KEY"
	EnvKeyName    = "PQC_KEY_NAME"

	EnvDEBUG  = "PQC_DEBUG"
	EnvKMSKey = "PQC_KMS_KEY"

	KeyName    = "key_name"
	PublicKey  = "public_key"
	PrivateKey = "private_key"

	KeyVersion = 1

	DEBUG = "debug"
)

const ()

var ()
