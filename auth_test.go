package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/segmentio/ksuid"
)

func TestAuth(t *testing.T) {
	uid, err := ksuid.NewRandom()
	if err != nil {
		t.Fatal(err)
	}

	id := uid.String()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer := NewRequestSigner[map[string]string](privateKey, "Authorization")
	verifier := NewRequestVerifier[map[string]string](publicKey, "Authorization")

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	meta := map[string]string{
		"key": "value",
	}

	if err := signer(req, id, &meta); err != nil {
		t.Fatal(err)
	}

	i, m := verifier(req)

	if id != i {
		t.Fatal("nope")
	}

	if (*m)["key"] != "value" {
		t.Fatal("nah")
	}
}
