package eddsa

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEd25519(t *testing.T) {
	privateKey, err := Ed25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	if len(privateKey.D) != 64 || len(privateKey.X) != 32 {
		t.Fatalf("bad length")
	}

	if bytes.Compare(privateKey.D[32:64], privateKey.X) != 0 {
		t.Fatalf("bad private key: %v %v", privateKey.D, privateKey.X)
	}

	b := make([]byte, 94)
	rand.Read(b)

	sig, err := privateKey.Sign(b)
	if err != nil {
		panic(err)
	}

	ok := privateKey.Verify(b, sig)
	if !ok {
		t.Fatalf("did not verify")
	}

	pub, ok := privateKey.Public().(*PublicKey)
	if !ok || pub != &privateKey.PublicKey {
		t.Fatalf("...")
	}

	t.Logf("%v", privateKey)
	t.Logf("%v", sig)

	pa := Private25519(privateKey)
	if bytes.Compare(pa[:], privateKey.D) != 0 {
		t.Fatalf("private25519")
	}

	puba := Public25519(&privateKey.PublicKey)
	if bytes.Compare(puba[:], privateKey.X) != 0 {
		t.Fatalf("public25519")
	}
}
