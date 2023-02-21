package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/segmentio/ksuid"
	"encoding/json"
	"crypto/sha256"
	"encoding/hex"
	"bytes"
)

func NewRequestSigner[T any](
	privateKey ed25519.PrivateKey,
	header string,
) func(r *http.Request, id string, meta T) error {

	return func(r *http.Request, id string, meta T) error {
		nonce, err := ksuid.NewRandom()
		if err != nil {
			return err
		}

		payload, err := json.Marshal(meta)
		if err != nil {
			return err
		}

		enc := make([]byte, base64.RawURLEncoding.EncodedLen(len(payload)))
		base64.RawURLEncoding.Encode(enc, payload)

		sum := sha256.New()
		if _, err := sum.Write(enc); err != nil {
			return err
		}

		checksum := hex.EncodeToString(sum.Sum(nil))
		msg := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%v_%v_%v", nonce.String(), id, checksum)))
		sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(msg)))

		r.Header.Set(header, fmt.Sprintf("%v.%v.%v", msg, string(enc), sig))

		return nil
	}
}

func NewRequestVerifier[T any](publicKey ed25519.PublicKey, header string) func(r *http.Request) (string, *T) {
	return func(r *http.Request) (string, *T) {

		parts := strings.Split(r.Header.Get(header), ".")
		if len(parts) != 3 {
			return "", nil
		}

		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
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

		ourChecksum := sha256.New()
		if _, err := ourChecksum.Write([]byte(parts[1])); err != nil {
			return "", nil
		}

		bp, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", nil
		}

		payload := new(T)
		if err := json.Unmarshal(bp, &payload); err != nil {
			return "", nil
		}

		parts = strings.Split(string(msg), "_")
		if len(parts) != 3 {
			return "", nil
		}

		theirChecksum, err := hex.DecodeString(parts[2])
		if err != nil {
			return "", nil
		}

		if !bytes.Equal(ourChecksum.Sum(nil), theirChecksum) {
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

		return parts[1], payload
	}
}
