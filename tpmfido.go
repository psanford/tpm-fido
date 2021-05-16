package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"math/big"
	"time"

	"github.com/psanford/tpm-fido/attestation"
	"github.com/psanford/tpm-fido/fidoauth"
	"github.com/psanford/tpm-fido/fidohid"
	"github.com/psanford/tpm-fido/pinentry"
	"github.com/psanford/tpm-fido/statuscode"
	"golang.org/x/crypto/chacha20poly1305"
)

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
var (
	masterPrivateKey []byte
	signCounter      uint32
)

func main() {

	s := newServer()
	s.run()
}

type server struct {
	pe *pinentry.Pinentry
}

func newServer() *server {
	return &server{
		pe: pinentry.New(),
	}
}

func (s *server) run() {

	masterPrivateKey = mustRand(chacha20poly1305.KeySize)

	ctx := context.Background()
	token, err := fidohid.New(ctx, "tpm-fido")
	if err != nil {
		log.Fatalf("create fido hid error: %s", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		if evt.Error != nil {
			log.Printf("got token error: %s", err)
			continue
		}

		req := evt.Req

		if req.Command == fidoauth.CmdAuthenticate {
			log.Printf("got AuthenticatorAuthenticateCmd req")
			log.Printf("req: %+v", req.Authenticate)

			s.handleAuthenticate(ctx, token, evt)
		} else if req.Command == fidoauth.CmdRegister {
			log.Printf("got AuthenticatorRegisterCmd req: %+v", req)
			s.handleRegister(ctx, token, evt)
			log.Printf("done handleRegister: %+v", req)
		} else {
			log.Printf("unsupported request type: 0x%02x\n", req.Command)
			// send a not supported error for any commands that we don't understand.
			// Browsers depend on this to detect what features the token supports
			// (i.e. the u2f backwards compatibility)
			token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
		}
	}
}

func (s *server) handleAuthenticate(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	aead, err := chacha20poly1305.NewX(masterPrivateKey)
	if err != nil {
		panic(err)
	}

	if len(req.Authenticate.KeyHandle) < chacha20poly1305.NonceSizeX {
		log.Fatalf("incorrect size for key handle: %d smaller than nonce)", len(req.Authenticate.KeyHandle))
	}
	nonce := req.Authenticate.KeyHandle[:chacha20poly1305.NonceSizeX]
	cipherText := req.Authenticate.KeyHandle[chacha20poly1305.NonceSizeX:]

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, req.Authenticate.ApplicationParam[:]...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	childPrivateKey, err := aead.Open(nil, nonce, cipherText, sum)
	if err != nil {
		log.Printf("decrypt key handle failed")

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case fidoauth.CtrlCheckOnly,
		fidoauth.CtrlDontEnforeUserPresenceAndSign,
		fidoauth.CtrlEnforeUserPresenceAndSign:
	default:
		log.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			log.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	if req.Authenticate.Ctrl == fidoauth.CtrlCheckOnly {
		// check if the provided key is known by the token
		log.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			log.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == fidoauth.CtrlEnforeUserPresenceAndSign {

		pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Auth", req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam)

		if err != nil {
			log.Printf("pinentry err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)

			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					log.Printf("Got pinentry result err: %s", result.Error)
				}

				// Got user cancelation, we want to propagate that so the browser gives up.
				// This isn't normally supported by a key so there's no status code for this.
				// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					log.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	signCounter++

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	var ecdsaKey ecdsa.PrivateKey

	ecdsaKey.D = new(big.Int).SetBytes(childPrivateKey)
	ecdsaKey.PublicKey.Curve = elliptic.P256()
	ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = ecdsaKey.PublicKey.Curve.ScalarBaseMult(ecdsaKey.D.Bytes())

	sig, err := ecdsa.SignASN1(rand.Reader, &ecdsaKey, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write auth response err: %s", err)
		return
	}
}

func (s *server) handleRegister(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()
	req := evt.Req

	log.Printf("register start pin entry")
	pinResultCh, err := s.pe.ConfirmPresence("FIDO Confirm Register", req.Register.ChallengeParam, req.Register.ApplicationParam)

	if err != nil {
		log.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				log.Printf("Got pinentry result err: %s", result.Error)
			}

			log.Printf("pinentry got not ok")

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				log.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		registerSite(parentCtx, token, evt)
	case <-ctx.Done():
		log.Printf("register: short token timeout")
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		log.Printf("done WriteResponse statuscode.ConditionsNotSatisfied")
		if err != nil {
			log.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.AuthEvent) {
	req := evt.Req

	curve := elliptic.P256()

	childPrivateKey, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}

	metadata := []byte("fido_wrapping_key")
	metadata = append(metadata, req.Register.ApplicationParam[:]...)
	h := sha256.New()
	h.Write(metadata)
	sum := h.Sum(nil)

	aead, err := chacha20poly1305.NewX(masterPrivateKey)
	if err != nil {
		panic(err)
	}

	nonce := mustRand(chacha20poly1305.NonceSizeX)
	encryptedChildPrivateKey := aead.Seal(nil, nonce, childPrivateKey, sum)

	keyHandle := make([]byte, 0, len(nonce)+len(encryptedChildPrivateKey))
	keyHandle = append(keyHandle, nonce...)
	keyHandle = append(keyHandle, encryptedChildPrivateKey...)

	if len(keyHandle) > 255 {
		panic("keyHandle is too big")
	}

	childPubKey := elliptic.Marshal(curve, x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sigR, sigS, err := ecdsa.Sign(rand.Reader, attestation.PrivateKey, sigHash.Sum(nil))
	if err != nil {
		log.Fatalf("attestation sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	sig := elliptic.Marshal(elliptic.P256(), sigR, sigS)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		log.Printf("write register response err: %s", err)
		return
	}

}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}
