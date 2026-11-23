// Package envelope is the one source of the OpenCore keystore envelope format, shared by opencloud
// (pkg/keystore, the key store of the IdP), opendock (the keystore of the dApps) and services that open
// what was sealed for them (opendock/OPENCORE_KEYSTORE.md §9, §11.8, decision E-K8).
//
// Suite of version 1: HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
// A sealed secret is bound to the recipient key id and to a caller-chosen context (for a content key: the
// id of the keystore entry), so an envelope cannot be replayed for another entry or another recipient.
//
// Moved unchanged from opencloud pkg/keystore/envelope.go (kosmos, 2026-11-17); the byte format and the
// HPKE info are the same, envelopes sealed before the move still open.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// SuiteX25519AES256GCM names the only envelope suite of version 1.
const SuiteX25519AES256GCM = "HPKE-X25519-SHA256-A256GCM"

// Version is the envelope format version.
const Version = 1

// Info prefixes: what a sealed secret is. Part of the HPKE info, so a secret sealed for one purpose does
// not open for another.
const (
	PurposeContentKey    = "opencore/keystore/v1/cek"
	PurposeSessionSecret = "opencore/keystore/v1/session"
	// PurposeEntry binds the AES-GCM ciphertext of a keystore entry to its id (associated data).
	PurposeEntry = "opencore/keystore/v1/entry"
)

const (
	jwkCurveX25519 = "X25519"
	// X25519KeySize is the size of X25519 public and private keys in bytes.
	X25519KeySize = 32
	// ContentKeySize is the size of a content key (AES-256) in bytes.
	ContentKeySize = 32
)

// ErrEnvelope is returned when an envelope cannot be opened: wrong recipient, wrong context, tampered data
// or an unsupported format. The cause is not told apart on purpose.
var ErrEnvelope = errors.New("envelope: cannot be opened")

// ErrEntry is returned when an entry ciphertext cannot be decrypted.
var ErrEntry = errors.New("envelope: entry cannot be decrypted")

// Envelope carries a secret sealed for exactly one recipient key.
type Envelope struct {
	Version int    `json:"v"`
	Suite   string `json:"suite"`
	KeyID   string `json:"kid"`
	Sealed  []byte `json:"sealed"` // HPKE encapsulated key followed by the ciphertext
}

// Recipient is a published public key: its key id and the X25519 public key (32 bytes).
type Recipient struct {
	KeyID     string
	PublicKey []byte
}

// KeyID returns the RFC 7638 JWK thumbprint (SHA-256, base64url) of an X25519 public key. It is the stable
// identifier under which a key is published in a directory.
func KeyID(publicKey []byte) (string, error) {
	if len(publicKey) != X25519KeySize {
		return "", fmt.Errorf("envelope: public key must be %d bytes, got %d", X25519KeySize, len(publicKey))
	}
	return jwkThumbprint(jwkCurveX25519, publicKey), nil
}

// RecipientFor builds a recipient from a raw X25519 public key, with its key id.
func RecipientFor(publicKey []byte) (Recipient, error) {
	keyID, err := KeyID(publicKey)
	if err != nil {
		return Recipient{}, err
	}
	return Recipient{KeyID: keyID, PublicKey: publicKey}, nil
}

// JWKThumbprint returns the RFC 7638 thumbprint (SHA-256, base64url) of an OKP public key on the named curve
// (X25519, Ed25519).
func JWKThumbprint(curve string, publicKey []byte) string {
	return jwkThumbprint(curve, publicKey)
}

func jwkThumbprint(curve string, publicKey []byte) string {
	// RFC 7638: required members in lexicographic order, no whitespace.
	canonicalJWK := fmt.Sprintf(`{"crv":"%s","kty":"OKP","x":"%s"}`, curve, base64.RawURLEncoding.EncodeToString(publicKey))
	digest := sha256.Sum256([]byte(canonicalJWK))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// SealContentKey seals a content key for a recipient. Senders (depositing an entry) and a keystore
// (re-encryption for a recipient) use the same function.
func SealContentKey(recipient Recipient, entryContext string, contentKey []byte) (Envelope, error) {
	return Seal(recipient, PurposeContentKey, entryContext, contentKey)
}

// OpenContentKey opens an envelope with the recipient's private key.
func OpenContentKey(recipientPrivateKey []byte, sealedEnvelope Envelope, entryContext string) ([]byte, error) {
	return Open(recipientPrivateKey, PurposeContentKey, entryContext, sealedEnvelope)
}

// SealSessionSecret seals a session secret for a service; the context is the user id.
func SealSessionSecret(recipient Recipient, userID string, sessionSecret []byte) (Envelope, error) {
	return Seal(recipient, PurposeSessionSecret, userID, sessionSecret)
}

// OpenSessionSecret opens a session secret sealed for a service; the context is the user id.
func OpenSessionSecret(servicePrivateKey []byte, sealedEnvelope Envelope, userID string) ([]byte, error) {
	return Open(servicePrivateKey, PurposeSessionSecret, userID, sealedEnvelope)
}

// Seal seals plaintext for a recipient under a purpose and a binding context.
func Seal(recipient Recipient, purpose, bindingContext string, plaintext []byte) (Envelope, error) {
	recipientKeyID, err := KeyID(recipient.PublicKey)
	if err != nil {
		return Envelope{}, err
	}
	if recipient.KeyID != recipientKeyID {
		return Envelope{}, fmt.Errorf("envelope: key id %q does not match its public key", recipient.KeyID)
	}
	ecdhPublicKey, err := ecdh.X25519().NewPublicKey(recipient.PublicKey)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: invalid recipient public key: %w", err)
	}
	hpkePublicKey, err := hpke.NewDHKEMPublicKey(ecdhPublicKey)
	if err != nil {
		return Envelope{}, err
	}
	sealed, err := hpke.Seal(hpkePublicKey, hpke.HKDFSHA256(), hpke.AES256GCM(), Info(purpose, recipientKeyID, bindingContext), plaintext)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Version: Version, Suite: SuiteX25519AES256GCM, KeyID: recipientKeyID, Sealed: sealed}, nil
}

// Open opens an envelope sealed under a purpose and a binding context.
func Open(recipientPrivateKey []byte, purpose, bindingContext string, sealedEnvelope Envelope) ([]byte, error) {
	if sealedEnvelope.Version != Version || sealedEnvelope.Suite != SuiteX25519AES256GCM {
		return nil, ErrEnvelope
	}
	ecdhPrivateKey, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey)
	if err != nil {
		return nil, ErrEnvelope
	}
	// The key id inside the info is derived from the private key, not taken from the envelope: an envelope
	// relabelled for another recipient fails.
	recipientKeyID := jwkThumbprint(jwkCurveX25519, ecdhPrivateKey.PublicKey().Bytes())
	if sealedEnvelope.KeyID != recipientKeyID {
		return nil, ErrEnvelope
	}
	hpkePrivateKey, err := hpke.NewDHKEMPrivateKey(ecdhPrivateKey)
	if err != nil {
		return nil, ErrEnvelope
	}
	plaintext, err := hpke.Open(hpkePrivateKey, hpke.HKDFSHA256(), hpke.AES256GCM(), Info(purpose, recipientKeyID, bindingContext), sealedEnvelope.Sealed)
	if err != nil {
		return nil, ErrEnvelope
	}
	return plaintext, nil
}

// Info builds the HPKE info (and associated data elsewhere). Each part is length-prefixed (4 bytes, big
// endian) so that no two different (purpose, key id, context) triples yield the same bytes.
func Info(purpose, keyID, bindingContext string) []byte {
	info := make([]byte, 0, len(purpose)+len(keyID)+len(bindingContext)+12)
	for _, part := range []string{purpose, keyID, bindingContext} {
		partLength := uint32(len(part))
		info = append(info, byte(partLength>>24), byte(partLength>>16), byte(partLength>>8), byte(partLength))
		info = append(info, part...)
	}
	return info
}

// NewContentKey returns a fresh random content key.
func NewContentKey() ([]byte, error) {
	contentKey := make([]byte, ContentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, err
	}
	return contentKey, nil
}

// EncryptEntry encrypts the plaintext of a keystore entry with its content key (AES-256-GCM), bound to the
// entry id as associated data.
func EncryptEntry(contentKey []byte, entryID string, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := newAESGCM(contentKey)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, Info(PurposeEntry, "", entryID)), nil
}

// DecryptEntry reverses EncryptEntry.
func DecryptEntry(contentKey []byte, entryID string, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := newAESGCM(contentKey)
	if err != nil {
		return nil, ErrEntry
	}
	if len(nonce) != aead.NonceSize() {
		return nil, ErrEntry
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, Info(PurposeEntry, "", entryID))
	if err != nil {
		return nil, ErrEntry
	}
	return plaintext, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != ContentKeySize {
		return nil, fmt.Errorf("envelope: key must be %d bytes, got %d", ContentKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
