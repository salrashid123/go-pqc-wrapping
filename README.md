## AEAD encryption using Post Quantum Cryptography (ML-KEM)

This is a simple go library and cli using `ML-KEM` to wrap encrypt/decrypt arbitrary data.  

This is basically hybrid encryption where an `ML-KEM` keypair's public key is used to generate a `sharedSecret` which is used as an `AES-GCM` encryption key ultimately used to encrypt the data.

It uses the standard `go1.24.0+` [crypto/mlkem](https://pkg.go.dev/crypto/mlkem@go1.24.0) library formatted for compliance with Hashicorp [go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping) library set

This library also supports Google Cloud KMS's support for `ML-KEM`

>> NOTE: this library is note supported by Google

Also see:

* [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)
* [crypto: post-quantum support roadmap](https://github.com/golang/go/issues/64537)
* Key Encapsulation [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
* [Internet X.509 Public Key Infrastructure - Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/08/)
* [Post-Quantum Cryptography (PQC) scratchpad](https://github.com/salrashid123/pqc_scratchpad)

---

* [Usage](#usage)
  - [Key Generation](#key-generation)
  - [CLI](#cli)
  - [Library](#library)
    - [Encrypt](#encrypt)
    - [Decrypt](#decrypt)
* [Wrapped Key format](#wrapped-key-format)
  - [Client Data](#client-data)
  - [Versions](#versions)
* [GCP KMS](#gcp-kms)
* [Build](#build)
* [Openssl key formats](#openssl-key-formats)
* [References](#references)

---

## Usage

If you want to encrypt data intended for a remote system, the remote system must first generate an `ML-KEM` key pair and share the public key

If Bob wants to encrypt data for Alice

Alice generates `MK-KEM` keypair (`pub.pem`, `priv.pem`)

Alice shares `pub.pem` with Bob

Encrypt (Bob):

1. generate encapsulation data 
   
   `kemSharedSecret, kemCipherText = ML_KEM_Encapsulate( pub.pem )` 

2. Use `kemSharedSecret` as the AEAD key to encrypt `plainText`

   `cipherText = AEAD_Encrypt( kemSharedSecret, plainText )`

3.  Bob sends `[ kemCipherText, cipherText ]` to Alice

Decrypt (Alice):

4. `kemSharedSecret = ML_KEM_Decapsulate( priv.pem, kemCipherText )`

5. `plaintext = AEAD_Decrypt( kemSharedSecret, cipherText )`


### Key Generation

This repo only support PEM encoded files which encodes the `bare-seed`.  See the [#openssl-key-formats](#openssl-key-formats) section below.

The PEM file itself is described in [draft-ietf-lamps-kyber-certificates-11](https://datatracker.ietf.org/doc/draft-ietf-lamps-kyber-certificates/11/) where just the `seed` is required (see seciton `C.1.2.1.  Seed Format`)

To generate a key, you can either use [crypto/mlkem.GenerateKey768](https://pkg.go.dev/crypto/mlkem#GenerateKey768) or openssl 3.5.0+ which you can get in a dockerfile format at [Post-Quantum Cryptography (PQC) scratchpad](https://github.com/salrashid123/pqc_scratchpad).

If you want to generate a new keypair in go, see [example/util](example/util) folder.

```bash
cd util/to_pem
go run main.go --keyType=mlkem768 \
   --private=priv-ml-kem-768-bare-seed.pem \
   --public=pub-ml-kem-768-bare-seed.pem
```

or with openssl

```bash
$ openssl -version
    OpenSSL 3.5.0-dev  (Library: OpenSSL 3.5.0-dev )

### generate ML-KEM-768
$ openssl genpkey  -algorithm mlkem768 \
   -provparam ml-kem.output_formats=bare-seed \
   -out priv-ml-kem-768-bare-seed.pem

openssl pkey  -in priv-ml-kem-768-bare-seed.pem  -pubout -out pub-ml-kem-768-bare-seed.pem
```

If your openssl version does not support mlkem, you can use a dockerfile

```bash
docker run -v /dev/urandom:/dev/urandom -ti salrashid123/openssl-pqs:3.5.0-dev
```

### CLI

Prebuilt, signed binaries can be found under the [Releases](https://github.com/salrashid123/go-pqc-wrapping/releases) page,  To run directly, you will need `go1.24.0+`

CLI Options:

| Option | Description |
|:------------|-------------|
| **`-mode`** | operation mode `encrypt or decrypt` (default: `encrypt`) |
| **`-dataToEncrypt`** | some small text to encrypt (default ``) |
| **`-key`** | Public key to encrypt or private key to decrypt  (default ``) |
| **`-aad`** | AAD aadditional data to encrypt/decrytp (default ``) |
| **`-clientData`** | JSON to include as client_data (default ``) |
| **`-in`** | file to read encrypted data from (default: ``) |
| **`-out`** | File to write encrypted data to (default: ``) |
| **`-keyName`** | any arbitrary name to give to the key (default: ``) |
| **`-debug`** | toggle debug mode (default: `false`) |

---

```bash
## to build manually
go build  -o go-pqc-wrapping cmd/main.go

## Encrypt
./go-pqc-wrapping --mode=encrypt --aad=myaad \
 --key=file://`pwd`/example/certs/pub-ml-kem-768-bare-seed.pem \
 --dataToEncrypt="bar" --keyName=mykey --out=/tmp/encrypted.json --debug

## decrypt
./go-pqc-wrapping  --mode=decrypt --aad=myaad \
 --key=file://`pwd`/example/certs/bare-seed-768.pem \
 --in=/tmp/encrypted.json --out=/tmp/decrypted.txt --debug
```

### Library

#### Encrypt

To encrypt, you need to provide the PEM format of the ML-KEM public key:

```golang
	pubPEMBytes, err := os.ReadFile(*publicKey)

	wrapper := pqcwrap.NewWrapper()
	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(pubPEMBytes)), pqcwrap.WithKeyName("myname"))

	blobInfo, err := wrapper.Encrypt(ctx, []byte(*dataToEncrypt), wrapping.WithAad([]byte("myaad")))

	fmt.Printf("Encrypted: %s\n", base64.StdEncoding.EncodeToString(blobInfo.Ciphertext))
```

#### Decrypt

To decrypt, you need to provide the PEM `bare-seed` format of the public key.
```golang
	privatePEMBytes, err := os.ReadFile(*privateKey)

	wrapper := pqcwrap.NewWrapper()

	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPrivateKey(string(privatePEMBytes)))

	b, err := os.ReadFile(*encryptedBlob)

	newBlobInfo := &wrapping.BlobInfo{}
	err = protojson.Unmarshal(b, newBlobInfo)

	plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, wrapping.WithAad([]byte("myaad")))

	fmt.Printf("Decrypted %s\n", string(plaintext))
```

see `example/` folder:

as library:

```bash
cd example
## Encrypt
go run encrypt/main.go --publicKey=certs/pub-ml-kem-768-bare-seed.pem

# Decrypt
go run decrypt/main.go --privateKey="certs/bare-seed-768.pem"
```

#### Client Data

You can also embed additional arbitrary JSON data into the protobuf as `client_data` structure.  This data is **not** included in the encryption and is not directly related to the `AdditionalData (AAD)` associated with aes-gcm.

The client data field is instead just unencrypted/unverified data you can associate with the encoded key.  

However, you can canonicalize the `client_data` as JSON, hash that and use that hash value as the AAD.  In effect, the client_data can then be used as part of the integrity calculation.

For example, if the client data is

```json
	"clientData": {
		"location": {
			"region": "us",
			"zone": "central"
		},
		"provider": "pqc"
	}
```

then you can encrypt/decrypt as:

```bash
./go-pqc-wrapping --mode=encrypt --aad=myaad \
 --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
 --key=file://`pwd`/example/certs/pub-ml-kem-768-bare-seed.pem \
 --dataToEncrypt="bar" --keyName=mykey --out=/tmp/encrypted.json --debug

## decrypt
./go-pqc-wrapping  --mode=decrypt --aad=myaad \
 --clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
 --key=file://`pwd`/example/certs/bare-seed-768.pem \
 --in=/tmp/encrypted.json --out=/tmp/decrypted.txt --debug
```

as library, see `example/client_data`.   The examples below encodes the hash of the client_data as the AAD itself

```bash
cd example/
go run client_data/encrypt/main.go -publicKey=certs/pub-ml-kem-768-bare-seed.pem \
  -clientData="{\"provider\": \"pqc\", \"location\": { \"region\": \"us\", \"zone\": \"central\"}}" \
  -dataToEncrypt=foo \
  -encryptedBlob=/tmp/encrypted.json

# decrypt
go run client_data/decrypt/main.go \
  --privateKey=certs/bare-seed-768.pem \
  -encryptedBlob=/tmp/encrypted.json \
  --clientData="{\"provider\": \"pqc\", \"location\": { \"zone\": \"central\",\"region\": \"us\"}}"
```

Note that you can specify the client data either in the overall wrapper config or during each encrypt/decrypt method.  If specified in the encrypt/decrypt methods, it takes priority.

specified in config:

```golang
	_, err = wrapper.SetConfig(ctx, pqcwrap.WithPublicKey(string(pubPEMBytes)),
		pqcwrap.WithClientData(*clientData))
```

in operation:

```golang
plaintext, err := wrapper.Decrypt(ctx, newBlobInfo, pqcwrap.WithClientData(*expectedClientData))
```

### GCP KMS

This library also support encapsulation using [GCP KMS MLKEM](https://docs.cloud.google.com/kms/docs/key-encapsulation-mechanisms) (yes, i'm aware [go-kms-wrapping](https://github.com/hashicorp/go-kms-wrapping) supports KMS but it doesn't yet support ML-KEM)


To use this mode, first create a kms key


```bash
gcloud kms keyrings create kem_kr --location=global

gcloud kms keys create kem_key_1 \
    --keyring kem_kr \
    --location global \
    --purpose "key-encapsulation" \
    --default-algorithm ml-kem-768 \
    --protection-level "software"


gcloud kms keys versions get-public-key 1 \
    --key kem_key_1 \
    --keyring kem_kr \
    --location global  \
    --output-file /tmp/kem_pub.nist \
    --public-key-format nist-pqc
```

The extract the public key into PEM format:

```bash
$ openssl --version
  OpenSSL 3.5.0-dev  (Library: OpenSSL 3.5.0-dev )

$ { echo -n "MIIEsjALBglghkgBZQMEBAIDggShAA==" | base64 -d ; cat /tmp/kem_pub.nist; } | openssl asn1parse -inform DER -in -
    0:d=0  hl=4 l=1202 cons: SEQUENCE          
    4:d=1  hl=2 l=  11 cons: SEQUENCE          
    6:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   17:d=1  hl=4 l=1185 prim: BIT STRING        

$ cd example/
$ { echo -n "MIIEsjALBglghkgBZQMEBAIDggShAA==" | base64 -d ; cat /tmp/kem_pub.nist; } \
   | openssl pkey -inform DER -pubin -pubout -out certs/pub-ml-kem-768-kms.pem
```

then with cli

```bash
## Encrypt
./go-pqc-wrapping --mode=encrypt \
 --key=file://`pwd`/example/certs/pub-ml-kem-768-kms.pem \
 --dataToEncrypt="bar" --keyName=mykey --out=/tmp/encrypted.json --debug

## decrypt
./go-pqc-wrapping  --mode=decrypt \
 --key="gcpkms://projects/core-eso/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1" \
 --in=/tmp/encrypted.json --out=/tmp/decrypted.txt --debug
```

as library:

```bash
cd example
## Encrypt
go run encrypt/main.go --publicKey=certs/pub-ml-kem-768-kms.pem

# Decrypt
export PROJECT_ID=`gcloud config get-value core/project`
go run decrypt_kms/main.go \
   --kmsURI="gcpkms://projects/$PROJECT_ID/locations/global/keyRings/kem_kr/cryptoKeys/kem_key_1/cryptoKeyVersions/1"
```

### Wrapped Key format

There are two levels of encryption involved with this library and is best described in this flow:

-  Encrypt

1. Read the `ML-KEM` Public key and generate `sharedCiphertext` and `sharedSecret`

   ```golang
   ek, err := mlkem.NewEncapsulationKey768(pkix.PublicKey.Bytes)
   kemSharedSecret, kemCipherText = ek.Encapsulate()
   ```

2. Create new *direct* aead wrapper using `wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"` and set  `kemSharedSecret` as the key. `wrapaead` already includes the [iv into the ciphertext](https://github.com/hashicorp/go-kms-wrapping/blob/main/aead/aead.go#L242-L249) 

   ```golang
	w := wrapaead.NewWrapper()
	err := w.SetAesGcmKeyBytes(kemSharedSecret)
	cipherText, _ := w.Encrypt(ctx, plaintext, opt...)
   ```


* `ciphertext`: the encrypted data wrapped using `kemSharedSecret`  amd already includes the initialization vector
* `wrappedKey`: the ML-KEM `sharedCiphertext`

```json
{
	"ciphertext": "bQAifHrc2qo1WRpGW6vyWlKHd2QeTSt1WZZOxlHj7g==",
	"keyInfo": {
		"keyId": "myname",
		"wrappedKey": "eyJuYW1lIjoibXluYW1lIiwidmVyc2lvbiI6MSwidHlwZSI6Im1sX2tlbV83NjgiLCJrZW1DaXBoZXJUZXh0IjoiMk4yRldVeGtWdUtDY21RU1o3VDQ0amlrZkIrb2ZnTmZvVE0vMERudUJoREhvNG1ORnJYb2xMUndraGNqRG12Nk00WWt5b2JncElLTWRuOTVHUmk2WG0vRE15ZTBDNEdyRFEweCtRcU9vRndLYU9kK05wT2ZQNG1ERWRWK2EzdHlMREk2djVxSGRhMFZkSWNaMk5oMDZDOGkxQjlFNGNXcU1MRlh4VW5QTkUzY1EwS2RSZVA2RVZyQm0rNjRQRzdNSGZLVjEzdkQ3UUZIWGtMR2pUR0Jodk9IMWxPWWp2YStLZGdCSWlkMFV3MllDVjZuWFVQMHUyZC9xcHZqVURUMG1wN3FwVndlRExFWUxOWjNxbElFQTVPWXgydnMrYmpwa2NLYjR6WGN4dVhEcWhmZzZvRVEyMUtFa0dhOEtIWUdDVFB5cG5PUzZtclBHdGZOelJFTDllaG04cjVJNHE5U2xQUWUyM2MwZmp3d1BNSzVUOGJ2ZUFVT1RjZENmZ0RWcXptaU8zSWZTVzI5NmpPeXVMUzFOWitGVk9OYzZpeHhwUDNLT3hKUzVrTWF5d09BYndDSHh4YzZ0eTdjYVNScGlpY05Jak8rS3g4Mm91L0dJSE9aSE1qZ2dpbjQvMnRxTkNKVTMwakp2MDZXMnhFUE5rRkZWVjVESkpydDJEVnE4SW1TQ2ppd0NHYkxiQ1c4Q3lMRTY3T01LZTVuZ0FNbTdaTCtoYXdDYUcwWjRGYklhSWZXR3J0WVAwdFYrcW9tbTNDS09icVBIOUZ3bHg2YXRncy83SEsvNUNCN1lZeHN5ZjBnaUg0eExCRE1xMTBqdTVkMWxSbFBHNEhPanNDK0VSR1ljS2lxNnhFZkhucDJGdTI2ejhJdHN6QkxDV21YM2d2V2Z2T052ZTYvVkVNS2d0azBiaEtyTG5tdC9OQjNRTGpxbGZHUXZIRGtoRFNtNldPbmxpVGpvUzZLWVpYSGRPdmtZOTk0b2xXV2JobDBpU01mbUtvdW1JNUJNamFjMnN5bzJlZEs4dGtKZWx5YVEybStBM01IV2p5YkY0NVFMblB3NkxKMjJuUEVzanJRZ3RxR0c3NS92K0lITzBTSHUwSENpaHFNNmJ2U0VQN0VrV3FZSWx4RmVVeFB3TGMyNDMwWURHSG5kejgvWnIxcWdjY1Rycm9oTEI3dkRiOGlvNXI5bkNQMDZXaElnZ0c4SnJFaGhLa01ML3ZZblY0bmt0a0diLysvZjFZTjRiRklPMEVrOU1IeFpmYnJYZXl0U2VkQnZoWERMRUxhczN4NGw1VXYyMVZyNDh6aXAwRm9YV2RBSVVYL2RXOW11V0hhTWhndkd4b2pCS2ZVN0h2b3FZNUNCZUZ4cFhidWxtYi9sQlAwTllCSkQ5UVdjdU5MVEdBWjh5eXFjMzJFWG1qOCt6M2lnQjFWNTVBNWFmU0FESW9vTW9qd05nUmMyQStsT2Frcm5rMGZ6NERSaXpLU2xhUklyVVVFR2xQVlBtNFVya1pGTEZQZzlZY3B1WllpTEFjMkRIdklDMGhic2lRYUNQV051cm1XMzdmOHBDM1o3OS9ORVNHUkp5WUd3MmIwaVNzSDdFTStXMWtqaVUvZHA5UWRadkxHVjhYaEhMaHZSbXkwaDdnUmZJbnpjRVpxZnlKNklvc2NRY2U4b2RrbmIyMWlzcy9TZ3lKeUdCdVJ0bGV5cEt1UVRLeFVJVWVmVVkrUVZ6MENwZzVCOVl3bjNhK3VBYStrNjlQVldQZjFISW1ydVV0VTBtMUtiTitvQ1dRMHIwdy9LemUyVURERGJac0huOGlKS0FWV2J3b1BHRXlxUFNBM0xpaGVrNnJGektxODd5N2pWaU9YU0hiOTU4WGtSLzZxalFhVG5ZUWZVc3JzN1RPNDd3Y2pUMDB4cTluNGNUWTJmWUE9In0="
	}
}
```

If you base64decode the `wrappedKey`

* `kemCipherText` the `ML-KEM` ciphertext (eg `sharedCiphertext`). Once this is decapsulated, this becomes an AES GCM

The keyfile is:

```json
{
  "name": "myname",
  "version": 1,
  "type": "ml_kem_768",
  "kemCipherText": "2N2FWUxkVuKCcmQSZ7T44jikfB+ofgNfoTM/0DnuBhDHo4mNFrXolLRwkhcjDmv6M4YkyobgpIKMdn95GRi6Xm/DMye0C4GrDQ0x+QqOoFwKaOd+NpOfP4mDEdV+a3tyLDI6v5qHda0VdIcZ2Nh06C8i1B9E4cWqMLFXxUnPNE3cQ0KdReP6EVrBm+64PG7MHfKV13vD7QFHXkLGjTGBhvOH1lOYjva+KdgBIid0Uw2YCV6nXUP0u2d/qpvjUDT0mp7qpVweDLEYLNZ3qlIEA5OYx2vs+bjpkcKb4zXcxuXDqhfg6oEQ21KEkGa8KHYGCTPypnOS6mrPGtfNzREL9ehm8r5I4q9SlPQe23c0fjwwPMK5T8bveAUOTcdCfgDVqzmiO3IfSW296jOyuLS1NZ+FVONc6ixxpP3KOxJS5kMaywOAbwCHxxc6ty7caSRpiicNIjO+Kx82ou/GIHOZHMjggin4/2tqNCJU30jJv06W2xEPNkFFVV5DJJrt2DVq8ImSCjiwCGbLbCW8CyLE67OMKe5ngAMm7ZL+hawCaG0Z4FbIaIfWGrtYP0tV+qomm3CKObqPH9Fwlx6atgs/7HK/5CB7YYxsyf0giH4xLBDMq10ju5d1lRlPG4HOjsC+ERGYcKiq6xEfHnp2Fu26z8ItszBLCWmX3gvWfvONve6/VEMKgtk0bhKrLnmt/NB3QLjqlfGQvHDkhDSm6WOnliTjoS6KYZXHdOvkY994olWWbhl0iSMfmKoumI5BMjac2syo2edK8tkJelyaQ2m+A3MHWjybF45QLnPw6LJ22nPEsjrQgtqGG75/v+IHO0SHu0HCihqM6bvSEP7EkWqYIlxFeUxPwLc2430YDGHndz8/Zr1qgccTrrohLB7vDb8io5r9nCP06WhIggG8JrEhhKkML/vYnV4nktkGb/+/f1YN4bFIO0Ek9MHxZfbrXeytSedBvhXDLELas3x4l5Uv21Vr48zip0FoXWdAIUX/dW9muWHaMhgvGxojBKfU7HvoqY5CBeFxpXbulmb/lBP0NYBJD9QWcuNLTGAZ8yyqc32EXmj8+z3igB1V55A5afSADIooMojwNgRc2A+lOakrnk0fz4DRizKSlaRIrUUEGlPVPm4UrkZFLFPg9YcpuZYiLAc2DHvIC0hbsiQaCPWNurmW37f8pC3Z79/NESGRJyYGw2b0iSsH7EM+W1kjiU/dp9QdZvLGV8XhHLhvRmy0h7gRfInzcEZqfyJ6IoscQce8odknb21iss/SgyJyGBuRtleypKuQTKxUIUefUY+QVz0Cpg5B9Ywn3a+uAa+k69PVWPf1HImruUtU0m1KbN+oCWQ0r0w/Kze2UDDDbZsHn8iJKAVWbwoPGEyqPSA3Lihek6rFzKq87y7jViOXSHb958XkR/6qjQaTnYQfUsrs7TO47wcjT00xq9n4cTY2fYA="
}
```

- Decrypt

1. Initialize ML-KEM using private key and recover the `kemSharedSecret`
   ```golang
   dk, err := mlkem.NewDecapsulationKey768(prkix.PrivateKey)
   kemSharedSecret, err = dk.Decapsulate(wrappb.KemCipherText)
   ```

2. Create new *direct* aead wrapper using `wrapaead "github.com/hashicorp/go-kms-wrapping/v2/aead"` and set  `kemSharedSecret` as the key.

   ```golang
	w := wrapaead.NewWrapper()
	err := w.SetAesGcmKeyBytes(kemSharedSecret)
	plainText, _ := w.Decrypt(ctx, cipherText, opt...)
   ```

#### Versions

The following lists the [Version](https://github.com/salrashid123/go-pqc-wrapping/blob/main/common.go#L31) values used in the encoding of the key.

Its important to decrypt using a cli or library version which is consistent with the proto or key encoding formats.


| KeyVersion | Date |
|------------|-------------|
| 1 | `2/25/25` |
| 2 | `1/2/26` |

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

Openssl PEM files encodes a custom 'format' prefix as shown [here](hhttps://github.com/openssl/openssl/blob/master/providers/implementations/encode_decode/ml_kem_codecs.c#L92).

For example, if you generated the key with a `seed-only`, the PEM file will have a prefix of `0x8040` for the raw key:

```bash
$  openssl asn1parse -inform PEM -in  example/certs/bare-seed-768.pem 
    0:d=0  hl=2 l=  82 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  64 prim: OCTET STRING      [HEX DUMP]:67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E

$  openssl asn1parse -inform PEM -in  example/certs/seed-only-768.pem 
    0:d=0  hl=2 l=  84 cons: SEQUENCE          
    2:d=1  hl=2 l=   1 prim: INTEGER           :00
    5:d=1  hl=2 l=  11 cons: SEQUENCE          
    7:d=2  hl=2 l=   9 prim: OBJECT            :ML-KEM-768
   18:d=1  hl=2 l=  66 prim: OCTET STRING      [HEX DUMP]:804067E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E
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

Note, you can extract the `seed` from a key using openssl:

```bash
$ openssl pkey -in example/certs/seed-only-768.pem -text          
      ML-KEM-768 Private-Key:
      seed:
         67:e6:bc:81:c8:46:80:80:02:ce:d7:1b:bf:8a:8c:
         41:95:af:2a:37:61:4c:4c:81:c0:b6:49:60:1b:29:
         be:aa:33:cb:ff:21:4a:0d:c4:59:74:93:62:c8:b3:
         d4:dd:7c:75:4a:0d:61:1d:51:d3:44:9c:2f:a4:7c:
         1d:c4:9c:5e
```

Which as hex is `67E6BC81C846808002CED71BBF8A8C4195AF2A37614C4C81C0B649601B29BEAA33CBFF214A0DC459749362C8B3D4DD7C754A0D611D51D3449C2FA47C1DC49C5E`

Since this repo only supports the `bare-seed` key, you'll need to convert it

```bash
## create a key with default seed-priv (implicitly by default or by specifying  ml-kem.output_formats )
openssl genpkey  -algorithm mlkem768   -out priv-ml-kem-768-seed-priv.pem
openssl asn1parse -in priv-ml-kem-768-seed-priv.pem

openssl genpkey  -algorithm mlkem768 \
   -provparam ml-kem.output_formats=seed-priv \
   -out priv-ml-kem-768-seed-priv.pem
openssl asn1parse -in priv-ml-kem-768-seed-priv.pem

## print the  seed
openssl pkey -in priv-ml-kem-768-seed-priv.pem -text  

   ML-KEM-768 Private-Key:
   seed:
      bf:bd:29:76:bd:01:87:e3:75:0e:5c:46:4e:fc:e0:
      5a:0a:b6:ca:0a:b4:0c:f7:c4:90:08:1b:54:83:1f:
      12:18:25:50:15:7f:49:e0:24:7b:92:b7:b9:b2:de:
      49:21:74:53:71:9a:81:71:c6:cd:15:83:23:da:d2:
      c6:6d:ef:2b

### now convert
openssl pkey -in priv-ml-kem-768-seed-priv.pem \
   -provparam ml-kem.output_formats=bare-seed \
   -out priv-ml-kem-768-bare-seed.pem

### and veify the seed is the same
openssl pkey -in priv-ml-kem-768-bare-seed.pem -text
   ML-KEM-768 Private-Key:
   seed:
      bf:bd:29:76:bd:01:87:e3:75:0e:5c:46:4e:fc:e0:
      5a:0a:b6:ca:0a:b4:0c:f7:c4:90:08:1b:54:83:1f:
      12:18:25:50:15:7f:49:e0:24:7b:92:b7:b9:b2:de:
      49:21:74:53:71:9a:81:71:c6:cd:15:83:23:da:d2:
      c6:6d:ef:2b
```


For reference, the `example/util` folder contains two standalone examples of marshalling and unmarshalling the PEM formatted `bare-seed` 

* `example/util/to_pem/main.go`

  Generate a new mkKEM key in go and convert it to public private `bare-seed` PEM format

```bash
  go run util/to_pem/main.go -private /tmp/private.pem -public /tmp/public.pem
  go run encrypt/main.go -publicKey /tmp/public.pem
  go run decrypt/main.go -privateKey /tmp/private.pem
```

* `example/util/from_pem/main.go`

  Read `bare-seed` PEM formatted keys and use go to wrap/unwrap

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


