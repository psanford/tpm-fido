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
MIIBcTCCARagAwIBAgIJAIqK93XCOr/GMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM
CFNvZnQgVTJGMB4XDTE3MTAyMDIxNTEzM1oXDTI3MTAyMDIxNTEzM1owEzERMA8G
A1UEAwwIU29mdCBVMkYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5gjPmSDFB
Jap5rwDMdyqO4lCcWqQXxXtHBN+S+zt6ytC3amquoctXGuOOKZikTkT/gX8LFXVq
mMZIcvC4EziGo1MwUTAdBgNVHQ4EFgQU8bJw2i1BjqI2uvqQWqNempxTxD4wHwYD
VR0jBBgwFoAU8bJw2i1BjqI2uvqQWqNempxTxD4wDwYDVR0TAQH/BAUwAwEB/zAK
BggqhkjOPQQDAgNJADBGAiEApFdcnvfziaAunldkAvHDwNViRH461fZv/6tFlbYP
GEwCIQCS1PM8fMOKTgdr3hpqeQq/ysQK8NJZtPbFADEk8effHQ==
-----END CERTIFICATE-----
`

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
