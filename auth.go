package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/segmentio/ksuid"
)

type (
	RequestSigner   = func(r *http.Request, id string) error
	RequestVerifier = func(r *http.Request) string
)

func NewRequestSigner(privateKey ed25519.PrivateKey, header string) RequestSigner {
	return func(r *http.Request, id string) error {
		nonce, err := ksuid.NewRandom()
		if err != nil {
			return err
		}

		msg := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%v_%v", nonce.String(), id)))
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(msg)))

		r.Header.Set(header, fmt.Sprintf("%v.%v", msg, sig))

		return nil
	}
}

func NewRequestVerifier(publicKey ed25519.PublicKey, header string) RequestVerifier {
	return func(r *http.Request) string {
		parts := strings.Split(r.Header.Get(header), ".")
		if len(parts) != 2 {
			return ""
		}

		sig, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}

		if !ed25519.Verify(publicKey, []byte(parts[0]), sig) {
			return ""
		}

		msg, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return ""
		}

		parts = strings.Split(string(msg), "_")
		if len(parts) != 2 {
			return ""
		}

		nonce := ksuid.KSUID{}
		if err := nonce.UnmarshalText([]byte(parts[0])); err != nil {
			return ""
		}

		now := time.Now()
		notBefore := now.Add(-1 * time.Minute)
		notAfter := now.Add(1 * time.Minute)

		nt := nonce.Time()
		if nt.Before(notBefore) || nt.After(notAfter) {
			return ""
		}

		return parts[1]
	}
}
