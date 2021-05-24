package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

// this is the same cert used by github/SoftU2F
// https://github.com/github/SoftU2F/blob/master/SelfSignedCertificate/SelfSignedCertificate.m
// We resuse that cert to help reduce the ability to track
// an individual using this cert

var attestationPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIAOEKsf0zeNn3qBWxk9/OxXqfUvEg8rGl58qMZOtVzEJoAoGCCqGSM49
AwEHoUQDQgAE9pyrJBRLtO+H9w8jHFzU9XgErPjgxrKz41IYPYA5H2vSedJqTINk
dObC2iOT/6wdUDRsXCOQZVeTPsuT/27e0Q==
-----END PRIVATE KEY-----`

var attestationCertPem = `-----BEGIN CERTIFICATE-----
MIIBfjCCASSgAwIBAgIBATAKBggqhkjOPQQDAjA8MREwDwYDVQQDDAhTb2Z0IFUy
RjEUMBIGA1UECgwLR2l0SHViIEluYy4xETAPBgNVBAsMCFNlY3VyaXR5MB4XDTE3
MDcyNjIwMDkwOFoXDTI3MDcyNDIwMDkwOFowPDERMA8GA1UEAwwIU29mdCBVMkYx
FDASBgNVBAoMC0dpdEh1YiBJbmMuMREwDwYDVQQLDAhTZWN1cml0eTBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABPacqyQUS7Tvh/cPIxxc1PV4BKz44Mays+NSGD2A
OR9r0nnSakyDZHTmwtojk/+sHVA0bFwjkGVXkz7Lk/9u3tGjFzAVMBMGCysGAQQB
guUcAgEBBAQDAgMIMAoGCCqGSM49BAMCA0gAMEUCIQD+Ih2XuOrqErufQhSFD0gX
ZbXglZNeoaPWbQ+xbzn3IgIgZNfcL1xsOCr3ZfV4ajmwsUqXRSjvfd8hAhUbiErU
QXo=
-----END CERTIFICATE-----`

var (
	CertDer    []byte
	PrivateKey *ecdsa.PrivateKey
)

func init() {
	certDer, _ := pem.Decode([]byte(attestationCertPem))
	CertDer = certDer.Bytes

	privKeyDer, _ := pem.Decode([]byte(attestationPrivateKeyPem))

	var err error
	PrivateKey, err = x509.ParseECPrivateKey(privKeyDer.Bytes)
	if err != nil {
		panic(err)
	}
}
