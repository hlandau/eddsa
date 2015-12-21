package eddsa

import (
	"crypto"
	"github.com/agl/ed25519"
	"io"
	"reflect"
	"unsafe"
)

type ed25519Impl struct{}

// Ed25519 signature scheme.
//
//   Public key size:   32 bytes
//   Private key size:  64 bytes
//   Signature size:    64 bytes
//   Security level:    ~128 bits
//   Preferred prehash: SHA512
//
func Ed25519() Curve {
	return ed25519Impl{}
}

func (ed25519Impl) GenerateKey(rand io.Reader) (priv *PrivateKey, err error) {
	pk, sk, err := ed25519.GenerateKey(rand)
	if err != nil {
		return
	}

	priv = &PrivateKey{
		PublicKey: PublicKey{
			Curve: Ed25519(),
			X:     make([]byte, 32),
		},
		D: make([]byte, 64),
	}

	copy(priv.X, pk[:])
	copy(priv.D, sk[:])

	return
}

func (ed25519Impl) Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	if len(priv.D) != 64 {
		return nil, errInvalidPrivateKey
	}

	sig := ed25519.Sign(un64(priv.D), data)
	return sig[:], nil
}

func (ed25519Impl) Verify(pub *PublicKey, data, sig []byte) bool {
	if len(sig) != 64 || len(pub.X) != 32 {
		return false
	}

	return ed25519.Verify(un32(pub.X), data, un64(sig))
}

func (ed25519Impl) Name() string {
	return "Ed25519"
}

func (ed25519Impl) KeySize() (publicKeySize, privateKeySize, signatureSize int) {
	return 32, 64, 64
}

func (ed25519Impl) PreferredPrehash() (crypto.Hash, string) {
	return crypto.SHA512, "SHA512"
}

// Marshalling utilities.

// Returns the public key in the form preferred by agl/ed25519. If the key is
// not an Ed25519 key, returns nil.
//
// This is a reference to the array underlying X; changing the returned value
// will change X.
func Public25519(pub *PublicKey) *[32]byte {
	if _, ok := pub.Curve.(ed25519Impl); !ok {
		return nil
	}

	return un32(pub.X)
}

// Returns the private key in the form preferred by agl/ed25519. If the key is not
// an Ed25519 key, returns nil.
//
// This is a reference to the array underlying D; changing the returned value
// will change D.
//
// (Note that the first 32 bytes of Ed25519 private keys are actually the
// public key. This can be rederived from the private key, so private keys are
// actually compressible to 32 bytes if desired.)
func Private25519(priv *PrivateKey) *[64]byte {
	if _, ok := priv.Curve.(ed25519Impl); !ok {
		return nil
	}

	return un64(priv.D)
}

// Converts byteslice of at least 32 bytes into *[32]byte. Does not copy the
// data. Caller must ensure size is adequate.
func un32(s []byte) *[32]byte {
	if len(s) < 32 {
		panic("un32 called with non-32-byte slice")
	}

	return (*[32]byte)(unsafe.Pointer(reflect.ValueOf(s).Pointer()))
}

// Converts byteslice of at least 64 bytes into *[64]byte. Does not copy the
// data. Caller must ensure size is adequate.
func un64(s []byte) *[64]byte {
	if len(s) < 64 {
		panic("un64 called with non-64-byte slice")
	}

	return (*[64]byte)(unsafe.Pointer(reflect.ValueOf(s).Pointer()))
}
