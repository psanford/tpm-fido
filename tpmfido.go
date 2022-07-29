package main

import (
	"context"
	"flag"
	"log"

	"github.com/psanford/ctapkey"
	"github.com/psanford/ctapkey/pinentry"
	"github.com/psanford/tpm-fido/memory"
	"github.com/psanford/tpm-fido/tpm"
)

var backend = flag.String("backend", "tpm", "tpm|memory")
var device = flag.String("device", "/dev/tpmrm0", "TPM device path")

func main() {
	flag.Parse()
	s := newServer()
	s.Run(context.Background())
}

func newServer() *ctapkey.Server {
	var (
		signer ctapkey.Signer
		err    error
	)

	if *backend == "tpm" {
		signer, err = tpm.New(*device)
		if err != nil {
			panic(err)
		}
	} else if *backend == "memory" {
		signer, err = memory.New()
		if err != nil {
			panic(err)
		}
	}

	s := ctapkey.Server{
		Signer:   signer,
		PinEntry: pinentry.New(),
		Logger:   log.Default(),
	}
	return &s
}
