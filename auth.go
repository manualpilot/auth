package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/segmentio/ksuid"
)

func NewRequestSigner[T any](
	privateKey ed25519.PrivateKey,
	header string,
) func(r *http.Request, id string, meta *T) error {
	return func(r *http.Request, id string, meta *T) error {
		nonce, err := ksuid.NewRandom()
		if err != nil {
			return err
		}

		msg := ""
		if meta == nil {
			msg = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%v|%v", nonce.String(), id)))
		} else {
			payload, err := json.Marshal(*meta)
			if err != nil {
				return err
			}

			enc := base64.RawURLEncoding.EncodeToString(payload)
			msg = base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%v|%v|%v", nonce.String(), id, enc)))
		}

		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(msg)))
		r.Header.Set(header, fmt.Sprintf("%v.%v", msg, sig))
		return nil
	}
}

func NewRequestVerifier[T any](publicKey ed25519.PublicKey, header string) func(r *http.Request) (string, *T) {
	return func(r *http.Request) (string, *T) {
		parts := strings.Split(r.Header.Get(header), ".")
		if len(parts) != 2 {
			return "", nil
		}

		sig, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", nil
		}

		if !ed25519.Verify(publicKey, []byte(parts[0]), sig) {
			return "", nil
		}

		msg, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return "", nil
		}

		parts = strings.Split(string(msg), "|")
		if len(parts) < 2 {
			return "", nil
		}

		nonce := ksuid.KSUID{}
		if err := nonce.UnmarshalText([]byte(parts[0])); err != nil {
			return "", nil
		}

		now := time.Now()
		notBefore := now.Add(-1 * time.Minute)
		notAfter := now.Add(1 * time.Minute)

		nt := nonce.Time()
		if nt.Before(notBefore) || nt.After(notAfter) {
			return "", nil
		}

		if len(parts) != 3 {
			return parts[1], nil
		}

		bp, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return "", nil
		}

		payload := new(T)
		if err := json.Unmarshal(bp, &payload); err != nil {
			return "", nil
		}

		return parts[1], payload
	}
}
