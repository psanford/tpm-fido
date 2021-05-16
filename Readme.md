# tpm-fido

tpm-fido is FIDO token implementation for Linux that protects the token keys by using your system's TPM. tpm-fido uses Linux's [uhid](https://github.com/psanford/uhid) facility to emulate a USB HID device so that it is properly detected by browsers.

##  Implementation details

tpm-fido uses the TPM 2.0 API. The overall design is as follows:

On registration tpm-fido generates a new P256 primary key under the Owner hierarchy on the TPM. To ensure that the key is unique per site and registration, tpm-fido generates a random 32 byte seed for each registration. The primary key template is populated with unique values from a sha256 hkdf of the 32 byte random seed and the application parameter provided by the browser.

A signing child key is then generated from that primary key. The key handle returned to the caller is a concatenation of the child key's public and private key handles and the 32 byte seed.

On an authentication request, tpm-fido will attempt to load the primary key by initializing the hkdf in the same manner as above. It will then attempt to load the child key from the provided key handle. Any incorrect values or values created by a different TPM will fail to load.

## Status

tpm-fido has been tested to work with Chrome on Linux. It does not currently work with Firefox, but we do plan on supporting Firefox in the future.

## Building

```
# in the root directory of tpm-fido run:
go build
```

## Running

In order to run `tpm-fido` you will need permission to access `/dev/tpm0`. On Ubuntu systems, users with the group `plugdev` will have access to the TPM.

```
# as a user that has permission to read and write to /dev/tpm0:
./tpm-fido
```

## Dependencies

tpm-fido requires `pinentry` to be available on the system. If you have gpg installed you most likely already have `pinentry`.
