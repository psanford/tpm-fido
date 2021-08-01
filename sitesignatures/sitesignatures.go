package sitesignatures

import (
	"crypto/sha256"
	"fmt"
)

// from https://github.com/danstiner/rust-u2f/blob/master/u2f-core/src/known_app_ids.rs
// and https://github.com/github/SoftU2F/blob/master/SoftU2FTool/KnownFacets.swift
var reverseSignatures = map[[32]byte]string{
	hashURL("https://api-9dcf9b83.duosecurity.com"):             "duosecurity.com",
	hashURL("https://dashboard.stripe.com"):                     "dashboard.stripe.com",
	hashURL("https://demo.yubico.com"):                          "demo.yubico.com",
	hashURL("https://github.com/u2f/trusted_facets"):            "github.com",
	hashURL("https://gitlab.com"):                               "gitlab.com",
	hashURL("https://id.fedoraproject.org/u2f-origins.json"):    "id.fedoraproject.org",
	hashURL("https://keepersecurity.com"):                       "keepersecurity.com",
	hashURL("https://lastpass.com"):                             "lastpass.com",
	hashURL("https://mdp.github.io"):                            "mdp.github.io",
	hashURL("https://personal.vanguard.com"):                    "vanguard.com",
	hashURL("https://u2f.aws.amazon.com/app-id.json"):           "aws.amazon.com",
	hashURL("https://u2f.bin.coffee"):                           "u2f.bin.coffee",
	hashURL("https://vault.bitwarden.com/app-id.json"):          "vault.bitwarden.com",
	hashURL("https://www.dropbox.com/u2f-app-id.json"):          "dropbox.com",
	hashURL("https://www.fastmail.com"):                         "www.fastmail.com",
	hashURL("https://www.gstatic.com/securitykey/origins.json"): "google.com",

	hashURL("bin.coffee"):          "bin.coffee",
	hashURL("coinbase.com"):        "coinbase.com",
	hashURL("demo.yubico.com"):     "demo.yubico.com",
	hashURL("github.com"):          "github.com",
	hashURL("webauthn.bin.coffee"): "webauthn.bin.coffee",
	hashURL("webauthn.io"):         "webauthn.io",
}

func hashURL(url string) [32]byte {
	return sha256.Sum256([]byte(url))
}

func FromAppParam(sig [32]byte) string {
	site := reverseSignatures[sig]
	if site == "" {
		site = fmt.Sprintf("<unknown %x>", sig)
	}
	return site
}
