## Go-PQC-Wrapping - Go library for encrypting data using Post Quantum Cryptography (PQC)

This is a simple go library and cli using `ML-KEM` to wrap encrypt/decrypt arbitrary data.  

This is basically hybrid encryption where an `ML-KEM` keypair is used to wrap an `AES-GCM` encryption key which is ultimately used to encrypt the data.  Think of AES key as the `DEK` and the ML-KEM shared secret as the `KEK`.  See [this post](https://crypto.stackexchange.com/questions/114235/have-any-hybrid-encryption-schemes-been-defined-for-quantum-resistant-algorithms), [Hybrid Public Key Encryption RFC 9180](https://datatracker.ietf.org/doc/rfc9180/) [ML-KEM for HPKE](https://datatracker.ietf.org/doc/draft-connolly-cfrg-hpke-mlkem/)

It uses the standard `go1.24.0+` [crypto/mlkem](https://pkg.go.dev/crypto/mlkem@go1.24.0) library formatted for compliance with Hashicorp [go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping) library set


>> NOTE: this library is note supported by Google; its exprimental...caveat emptor.

Also see:

* [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)
* [crypto: post-quantum support roadmap](https://github.com/golang/go/issues/64537)
* Key Encapsulation [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
* [Internet X.509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/08/)

---

* [Usage](#usage)
  - [Key Generation](#key-generation)
  - [CLI](#cli)
  - [Library](#library)
    - [Encrypt](#encrypt)
    - [Decrypt](#decrypt)
* [Wrapped Key format](#wrapped-key-format)
* [Build](#build)
* [Openssl key formats](#openssl-key-formats)
* [References](#references)

---

## Usage

### Key Generation

This repo only support PEM encoded files which encodes the `bare-seed`.  See the [#openssl-key-formats](#openssl-key-formats) section below

To generate a key, you need openssl 3.5.0+ which you can get in a dockerfile format at [Post-Quantum Cryptography (PQC) scratchpad](https://github.com/salrashid123/pqc_scratchpad)

```bash
docker run -v /dev/urandom:/dev/urandom -ti salrashid123/openssl-pqs:3.5.0-dev

$ openssl -version
    OpenSSL 3.5.0-dev  (Library: OpenSSL 3.5.0-dev )

### generate ML-KEM-768
$ openssl genpkey  -algorithm mlkem768 \
   -provparam ml-kem.output_formats=bare-seed \
   -out priv-ml-kem-768-bare-seed.pem

openssl pkey  -in priv-ml-kem-768-bare-seed.pem  -pubout -out pub-ml-kem-768.pem
```

TODO: support [crypto/mlkem](https://pkg.go.dev/crypto/mlkem) keys converted `Binary()` and used as the inputs in addition to the openssl PEM format

### CLI

Prebuilt, signed binaries can be found under the [Releases](https://github.com/salrashid123/go-pqc-wrapping/releases) page,  To run directly, you will need `go1.24.0+`

```bash
## Encrypt
./go-pqc-wrapping --mode=encrypt \
 --key=example/certs/pub-ml-kem-768.pem \
 --dataToEncrypt="bar" --keyName=mykey --out=/tmp/encrypted.json --debug

## decrypt
./go-pqc-wrapping  --mode=decrypt \
 --key=example/certs/bare-seed.pem \
 --in=/tmp/encrypted.json --out=/tmp/decrypted.txt --debug
```

### Library

#### Encrypt

To encrypt, you need to provide the PEM format of the ML-KEM public key:

```golang
	pubPEMBytes, err := os.ReadFile(*publicKey)

	wrapper := pqcwrap.NewWrapper()
	_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		pqcwrap.PublicKey: string(pubPEMBytes),
		pqcwrap.KeyName:   "mykey",
	}))

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt))

	fmt.Printf("Encrypted: %s\n", base64.StdEncoding.EncodeToString(blobInfo.Ciphertext))
```

#### Decrypt

To decrypt, you need to provide the PEM `bare-seed` format of the public key.
```golang
	privatePEMBytes, err := os.ReadFile(*privateKey)

	wrapper := pqcwrap.NewWrapper()
	_, err = wrapper.SetConfig(ctx, wrapping.WithConfigMap(map[string]string{
		pqcwrap.PrivateKey: string(privatePEMBytes),
	}))

	b, err := os.ReadFile(*encryptedBlob)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo)

	fmt.Printf("Decrypted %s\n", string(plaintext))
```

### Wrapped Key format

There are two levels of encryption involved with this library and is best described in this flow:

**Encrypt(plaintext, kemPublicKey)**

1. Use `"github.com/hashicorp/go-kms-wrapping/v2"` encrypt the original plaintext.
   ```golang
   env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)
   innerEncryptionKey := env.Key
   innerIV := env.Iv
   innerCipherText := env.Ciphertext
   ```

2. Read the `ML-KEM` Public key and generate `sharedCiphertext` and `sharedSecret`
   ```golang
   ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
   kemSharedSecret, kemCipherText = ek.Encapsulate()
   ```

3. Create new AES-GCM key using `sharedSecret` as the key and encrypt `innerEncryptionKey`.  No KDF is needed (see [section 3.2](https://datatracker.ietf.org/doc/draft-connolly-cfrg-hpke-mlkem/))

   ```golang
   block, err := aes.NewCipher(kemSharedSecret)

   outerKey, err := cipher.NewGCM(block)

   wrappedRawKey = outerKey.Seal(nil, nonce, innerEncryptionKey, nil)
   wrappedRawKey = append(nonce, wrappedRawKey...)
   ```


So when you encrypt data, the original `innerCipherText` and wrapped `innerEncryptionKey` itself is saved in json format:

* `ciphertext`: the encrypted data using the inner key provided by `go-kms-wrapping` library (step 1)
* `wrappedKey`: the ML-KEM `sharedCiphertext` and the encrypted from of the inner key (step 2,3)

```json
{
	"ciphertext": "IXjZAsQCpzxSOKIaDOcsDEu0DQ==",
	"iv": "UGNX2IzIPzJ+XwPG",
	"keyInfo": {
		"keyId": "mykey",
		"wrappedKey": "eyJuYW1lIjoibXlrZXkiLCAidmVyc2lvbiI6MSwgInR5cGUiOiJtbF9rZW1fNzY4IiwgImtlbUNpcGhlclRleHQiOiIvbG5lMGRGKy9GL0tXdk1rK2hlZHJOZXorcllweTBVQlBlUkZrZ1V2TTUrY0dNNU9wSUt0c3NTc1ZkMEpxUXFZVzAzdUYrOTRSS1hsMURTN3pXREFzV2lzL28wcjRaQldKci9rNWlmMDRySVpqQ0lsb3FLRG9BbGhyZ0NmcVh6WG5PakF3T09UWkVRNDRZWlN3bVhoZmtieEtKUmFuV3ZjM0o1YlV3eUVyY0FnczlpbDdtY2RyTkVHM21wTk9zcmx5N2VSdGw5UFhVZ2VNWTBxeHE1dzJhdFpvUUxlK1BJWVRpcEdoK1FDYlpJNUlyamF1OUlhWWpteWNSdStTbmh4MWkzbUhxNHUrTVdGOTFFUmhyOU1RWUdYVHpoNmZCeVJCaUtIMVlnSGFZbUZXUUhuU0JOZ0pKWDdjTkt1eFVSQ1NsSU1KSWRTUUtoWk4wMkJEbWVsNTlMTnBxbStWaUNFRUdZZ0dXS3Vkam5VQTNGY1cyais2Q0JGZDdLdzhhZHZRa3drOThMN3c1ekl2Q05CbFVCNXRTcjZXMEcxVHo5NU9NVHBPVVpEYXd0OTh5NmRuZkZZMTlVYnBkd3BiNU5ib0FUd3kva041VHE4RjY5N0I1alZSZktDTEduWWozaVY3eDJLdkxwUXNoYjY2ajhrM0h2Mm12Y3VtYjVLSVF5UEpGSXRqaTlGK3JwS1lLU2MwZjhvVkpObkd4bVM0N2ZWUGhsZWt3OWw5dlBuNHNZTkpXRldFYjIwOGtOWEpJR05WWVVoTHBZVEVuY0xTVDRGaXkyTkpBYW5BdTJNZEtqOVVyOW03SzFkYXlBMXFpMzRXOGtrTnVTamp1ZzF1S3dvUDcxNFJoRjZJS3dZUUNabVA1bDdZUElDWGk3T2FLV3AxZDl5ODNlUkowaUhtVytJUWRtZmpuTzJ4TSt5YjRCeUQ0UWk3TDd1QVhnSEpSS09kNERXTWNWMW1PSjZnUkdibzI4VGlZM2dCS2VrM0QxbkxDTzRXb2gvSlJ1SU00VjM2ZlRwRG1QOEd4NVFmNVdoaGtjSzQvNnhqRE5IeDQ4YU54b3RQdWs5RXZFb1ZscVd1OWF0SVN4UHdzZ0ZBbS9wTWdmQjhFQTcySlFzNmZDN0xocFc2WnpYRGI1Wk5hT3RnTVBscG9tb01qeS9kYzUreWxDQzJzQUVuVThVaENXY1U0MjF3M0VQbktucFJCdzNaYk8ycWYyZ1ZmSldXRURpQ1JWd1NhM1JJbTNlTjI2N05UM3d1a0pNTUYxVzh0SnUyb1cvbXI5K01TSVF5M3FkLzlKRm9xbDdMakdSUGFkTXMvSEpVQ05DN2hwbmFXTGZVZG8yMDRock80Y1d3bHN5RFcybnRHenJ0QTIvSFFYeEhsT0pYbUhKNHN3NkhqWDZlMjFkdTI3NXArMWllVE1UNTc2L2lJRTJVTFhVQVEwSHFDYWkrbWoyTmdFQkVGR3dLNzVkaG9wWStSL3Rlb0dkNzFTOXI0cEp6cVJGVDIxM1UxZ3JmWjhnNFppcTZGOXFmdndkOXJMdzB0QkZ2d1JJWDBuTEcweGU2VmlzM0pIKy9CZ25NNzNQNmZ4K2xLaCtXLzdwdDROZ1U5b1Q3dlM1czNiUTNPNEpOWGZma2lORDN0UC9tR3ZHOTF2T0RTaFF4cldmZmFMY1RmbGRMNjVCS0luU0o1SExreWJDdUd2NFdkL21JeEIrazRKSklsemFPblJQOFpVN1lXaUJJRWpjWm8yMlVxOEEvbzUrWWNpenh6aEcxNzl0ZnJFd1FjT2FvaWxZWDdxZnlpVklKSTBDWXR0OU1VWU43TFFxdzVldE1GdEJuN2FCMkc2aTVVWDg0Q3ozcXBUcEdsd001ZXF2MkYwTHBrVFcrM1ZZSm9qaWQ2RXY1WnRWVURhZUw4UmN0NEtUanRPaVBIZz0iLCAid3JhcHBlZFJhd0tleSI6InN1cXdGM3FCK0VlWUY0bkJsbXIyT3V2aHNUZ0d5SjVFdkJRVG84YU1TSldja0JWazFBc0hNZ3VURTRYSXhTcjNabC9MQlYzUldtNHhpandJIn0="
	}
}
```

If you base64decode the `wrappedKey`

* `kemCipherText` the `ML-KEM` ciphertext (eg `sharedCiphertext`). Once this is decapsulated, this becomes an AES GCM outerKey
* `wrappedRawKey` AES-GCM encrypted innerkey which was encrypted itself by the outerKey.  When this value is decrypted gives, this is the key associated with the original ciphertext


The keyfile is:
```json
{
  "name": "mykey",
  "version": 1,
  "type": "ml_kem_768",
  "kemCipherText": "/lne0dF+/F/KWvMk+hedrNez+rYpy0UBPeRFkgUvM5+cGM5OpIKtssSsVd0JqQqYW03uF+94RKXl1DS7zWDAsWis/o0r4ZBWJr/k5if04rIZjCIloqKDoAlhrgCfqXzXnOjAwOOTZEQ44YZSwmXhfkbxKJRanWvc3J5bUwyErcAgs9il7mcdrNEG3mpNOsrly7eRtl9PXUgeMY0qxq5w2atZoQLe+PIYTipGh+QCbZI5Irjau9IaYjmycRu+Snhx1i3mHq4u+MWF91ERhr9MQYGXTzh6fByRBiKH1YgHaYmFWQHnSBNgJJX7cNKuxURCSlIMJIdSQKhZN02BDmel59LNpqm+ViCEEGYgGWKudjnUA3FcW2j+6CBFd7Kw8advQkwk98L7w5zIvCNBlUB5tSr6W0G1Tz95OMTpOUZDawt98y6dnfFY19Ubpdwpb5NboATwy/kN5Tq8F697B5jVRfKCLGnYj3iV7x2KvLpQshb66j8k3Hv2mvcumb5KIQyPJFItji9F+rpKYKSc0f8oVJNnGxmS47fVPhlekw9l9vPn4sYNJWFWEb208kNXJIGNVYUhLpYTEncLST4Fiy2NJAanAu2MdKj9Ur9m7K1dayA1qi34W8kkNuSjjug1uKwoP714RhF6IKwYQCZmP5l7YPICXi7OaKWp1d9y83eRJ0iHmW+IQdmfjnO2xM+yb4ByD4Qi7L7uAXgHJRKOd4DWMcV1mOJ6gRGbo28TiY3gBKek3D1nLCO4Woh/JRuIM4V36fTpDmP8Gx5Qf5WhhkcK4/6xjDNHx48aNxotPuk9EvEoVlqWu9atISxPwsgFAm/pMgfB8EA72JQs6fC7LhpW6ZzXDb5ZNaOtgMPlpomoMjy/dc5+ylCC2sAEnU8UhCWcU421w3EPnKnpRBw3ZbO2qf2gVfJWWEDiCRVwSa3RIm3eN267NT3wukJMMF1W8tJu2oW/mr9+MSIQy3qd/9JFoql7LjGRPadMs/HJUCNC7hpnaWLfUdo204hrO4cWwlsyDW2ntGzrtA2/HQXxHlOJXmHJ4sw6HjX6e21du275p+1ieTMT576/iIE2ULXUAQ0HqCai+mj2NgEBEFGwK75dhopY+R/teoGd71S9r4pJzqRFT213U1grfZ8g4Ziq6F9qfvwd9rLw0tBFvwRIX0nLG0xe6Vis3JH+/BgnM73P6fx+lKh+W/7pt4NgU9oT7vS5s3bQ3O4JNXffkiND3tP/mGvG91vODShQxrWffaLcTfldL65BKInSJ5HLkybCuGv4Wd/mIxB+k4JJIlzaOnRP8ZU7YWiBIEjcZo22Uq8A/o5+YcizxzhG179tfrEwQcOaoilYX7qfyiVIJI0CYtt9MUYN7LQqw5etMFtBn7aB2G6i5UX84Cz3qpTpGlwM5eqv2F0LpkTW+3VYJojid6Ev5ZtVUDaeL8Rct4KTjtOiPHg=",
  "wrappedRawKey": "suqwF3qB+EeYF4nBlmr2OuvhsTgGyJ5EvBQTo8aMSJWckBVk1AsHMguTE4XIxSr3Zl/LBV3RWm4xijwI"
}
```

**Decrypt(ciphertext,kemCipherText,wrappedRawKey,kemPrivateKey)**

1. Initialize ML-KEM using private key and recover the `kemSharedSecret`
   ```golang
   dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
   kemSharedSecret, err = dk.Decapsulate(wrappb.KemCipherText)
   ```

2. Initialize the outer AES-GCM Wrapper using the `kemSharedSecret` and decrypt `wrappedRawKey`
   ```golang
   block, err := aes.NewCipher(kemSharedSecret)
	outerKey, err := cipher.NewGCM(block)

   innerEncryptionKey, err := outerKey.Open(nil, nonce, wrappedRawKey,nil)
   ```

1. Use `"github.com/hashicorp/go-kms-wrapping/v2"` decrypt the original plaintext.
   ```golang
	envInfo := &wrapping.EnvelopeInfo{
		Key:        innerEncryptionKey,
		Iv:         innerIV,
		Ciphertext: ciphertext,
	}

	plaintext, err := wrapping.EnvelopeDecrypt(envInfo, opt...)
   ```

You maybe wondering why this library rewraps an AES key (eg why not directly use the KEM `sharedSecret`?), well this is just inherited from the underlying library (`go-kms-wrapping`) in which you have to call `env, err := wrapping.EnvelopeEncrypt(plaintext, opt...)`  with the provided plaintext and that itself creates the inner AES key.  Sure, i could just write my own plain wrapper library and forget about `go-kms-wrapping`'s constructs but i'm trying to be consistent with it.

### Build

If you want to regenerate with protoc:

```bash
$ /usr/local/bin/protoc --version
   libprotoc 25.1

$ go get -u github.com/golang/protobuf/protoc-gen-go   
$ go install github.com/golang/protobuf/protoc-gen-go   

$ /usr/local/bin/protoc -I ./ --include_imports \
   --experimental_allow_proto3_optional --include_source_info \
   --descriptor_set_out=pqcwrappb/wrap.proto.pb  \
   --go_out=paths=source_relative:. pqcwrappb/wrap.proto

$ go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
```

### Openssl key formats

Openssl PEM files encodes a custom 'format' prefix as shown [here](https://github.com/openssl/openssl/blob/ba90c491254fd3cee8a2f791fc191dcff27036c1/providers/implementations/encode_decode/ml_kem_codecs.c#L52C34-L52C38).

What this means is you need to account for this prefix.  For example, if you generated the key with a `seed-only`, the PEM file will have a prefix of `0x8040` for the raw key:

```bash
$  openssl asn1parse -inform PEM -in  example/certs/seed-only.pem 
    0:d=0  hl=2 l=  84 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  66 prim: OCTET STRING      [HEX DUMP]:804067E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E


$  openssl asn1parse -inform PEM -in  example/certs/bare-seed.pem 
    0:d=0  hl=2 l=  82 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  64 prim: OCTET STRING      [HEX DUMP]:67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E
```

For a list of all prefixes:

```cpp
static const ML_COMMON_PKCS8_FMT ml_kem_768_p8fmt[NUM_PKCS8_FORMATS] = {
    { "seed-priv",  0x09aa, 0, 0x308209a6, 0x0440, 6, 0x40, 0x04820960, 0x4a, 0x0960, 0,      0,     },
    { "priv-only",  0x0964, 0, 0x04820960, 0,      0, 0,    0,          0x04, 0x0960, 0,      0,     },
    { "oqskeypair", 0x0e04, 0, 0x04820e00, 0,      0, 0,    0,          0x04, 0x0960, 0x0964, 0x04a0 },
    { "seed-only",  0x0042, 2, 0x8040,     0,      2, 0x40, 0,          0,    0,      0,      0,     },
    { "bare-priv",  0x0960, 4, 0,          0,      0, 0,    0,          0,    0x0960, 0,      0,     },
    { "bare-seed",  0x0040, 4, 0,          0,      0, 0x40, 0,          0,    0,      0,      0,     },
};
```

#### Ml-KEM x509 Certificate

You can also encode the `ML-KEM` public key within a signed x509 certificate.  For details, see [ml-kem x509](https://github.com/salrashid123/pqc_scratchpad?tab=readme-ov-file#ml-kem) 

#### Verify Release Binary

If you download a binary from the "Releases" page, you can verify the signature with GPG:

```bash
gpg --keyserver keys.openpgp.org --recv-keys 3FCD7ECFB7345F2A98F9F346285AEDB3D5B5EF74

## to verify the checksum file for a given release:
wget https://github.com/salrashid123/go-pqc-wrapping/releases/download/v0.0.3/go-pqc-wrapping_0.0.3_checksums.txt
wget https://github.com/salrashid123/go-pqc-wrapping/releases/download/v0.0.3/go-pqc-wrapping_0.0.3_checksums.txt.sig

gpg --verify go-pqc-wrapping_0.0.3_checksums.txt.sig go-pqc-wrapping_0.0.3_checksums.txt
```

#### Verify Release Binary with github Attestation

You can also verify the binary using [github attestation](https://github.blog/news-insights/product-news/introducing-artifact-attestations-now-in-public-beta/)

For example, the attestation for releases `[@refs/tags/v0.0.3]` can be found at

* [https://github.com/salrashid123/go-pqc-wrapping/attestations](https://github.com/salrashid123/go-pqc-wrapping/attestations)

Then to verify:

```bash
wget https://github.com/salrashid123/go-pqc-wrapping/releases/download/v0.0.3/go-pqc-wrapping_0.0.3_linux_amd64
wget https://github.com/salrashid123/go-pqc-wrapping/attestations/5187009/download -O salrashid123-go-pqc-wrapping-attestation-5187009.json

gh attestation verify --owner salrashid123 --bundle salrashid123-go-pqc-wrapping-attestation-5187009.json  go-pqc-wrapping_0.0.3_linux_amd64 

      Loaded digest sha256:aad438184e9440d3b12c5d85eef2ede60138f74da28238369a037954a968a38c for file://go-pqc-wrapping_0.0.3_linux_amd64
      Loaded 1 attestation from salrashid123-go-pqc-wrapping-attestation-5187009.json

      The following policy criteria will be enforced:
      - Predicate type must match:................ https://slsa.dev/provenance/v1
      - Source Repository Owner URI must match:... https://github.com/salrashid123
      - Subject Alternative Name must match regex: (?i)^https://github.com/salrashid123/
      - OIDC Issuer must match:................... https://token.actions.githubusercontent.com

      ✓ Verification succeeded!

      The following 1 attestation matched the policy criteria

      - Attestation #1
      - Build repo:..... salrashid123/go-pqc-wrapping
      - Build workflow:. .github/workflows/release.yaml@refs/tags/v0.0.3
      - Signer repo:.... salrashid123/go-pqc-wrapping
      - Signer workflow: .github/workflows/release.yaml@refs/tags/v0.0.3
```

### References

 * [Go-TPM-Wrapping - Go library for encrypting data using Trusted Platform Module (TPM)](https://github.com/salrashid123/go-tpm-wrapping)


