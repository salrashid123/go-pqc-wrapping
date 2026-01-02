package pqcwrap

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

var (
	mlkem512_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	mlkem768_OID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
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
	KeyName    = "key_id"
	PublicKey  = "public_key"
	PrivateKey = "private_key"

	KeyVersion = 2

	DEBUG = "debug"
)

const ()

var ()
