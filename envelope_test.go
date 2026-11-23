package envelope

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
)

var updateVectors = flag.Bool("update", false, "testdata/vectors.json neu schreiben")

func testKeyPair(t *testing.T, seedByte byte) (privateKey []byte, recipient Recipient) {
	t.Helper()
	privateKey = bytes.Repeat([]byte{seedByte}, X25519KeySize)
	ecdhPrivateKey, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err = RecipientFor(ecdhPrivateKey.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, recipient
}

func TestContentKeyRoundTripAndBinding(t *testing.T) {
	privateKey, recipient := testKeyPair(t, 1)
	otherPrivateKey, otherRecipient := testKeyPair(t, 2)
	contentKey, err := NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealContentKey(recipient, "entry-1", contentKey)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenContentKey(privateKey, sealed, "entry-1")
	if err != nil || !bytes.Equal(opened, contentKey) {
		t.Fatalf("öffnen: %v", err)
	}
	if _, err := OpenContentKey(privateKey, sealed, "entry-2"); !errors.Is(err, ErrEnvelope) {
		t.Fatal("anderer Kontext darf nicht öffnen")
	}
	if _, err := OpenContentKey(otherPrivateKey, sealed, "entry-1"); !errors.Is(err, ErrEnvelope) {
		t.Fatal("anderer Empfänger darf nicht öffnen")
	}
	relabelled := sealed
	relabelled.KeyID = otherRecipient.KeyID
	if _, err := OpenContentKey(otherPrivateKey, relabelled, "entry-1"); !errors.Is(err, ErrEnvelope) {
		t.Fatal("umetikettierter Umschlag darf nicht öffnen")
	}
	if _, err := Open(privateKey, PurposeSessionSecret, "entry-1", sealed); !errors.Is(err, ErrEnvelope) {
		t.Fatal("anderer Zweck darf nicht öffnen")
	}
	if _, err := SealContentKey(Recipient{KeyID: "falsch", PublicKey: recipient.PublicKey}, "entry-1", contentKey); err == nil {
		t.Fatal("falsche kid muss abgelehnt werden")
	}
}

func TestEntryRoundTripAndBinding(t *testing.T) {
	contentKey, _ := NewContentKey()
	nonce, ciphertext, err := EncryptEntry(contentKey, "entry-1", []byte("geheim"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptEntry(contentKey, "entry-1", nonce, ciphertext)
	if err != nil || string(plaintext) != "geheim" {
		t.Fatalf("entschlüsseln: %v", err)
	}
	if _, err := DecryptEntry(contentKey, "entry-2", nonce, ciphertext); !errors.Is(err, ErrEntry) {
		t.Fatal("andere Eintrags-ID darf nicht entschlüsseln")
	}
}

// Feste Vektoren für andere Umsetzungen (Rust im Connector openfetchmail): ein Umschlag, der mit diesem Modul
// verschlossen wurde, muss sich dort öffnen lassen, und umgekehrt.
type vector struct {
	Description string   `json:"description"`
	PrivateKey  string   `json:"privateKey"` // base64url ohne Füllzeichen
	PublicKey   string   `json:"publicKey"`
	KeyID       string   `json:"kid"`
	Purpose     string   `json:"purpose"`
	Context     string   `json:"context"`
	InfoHex     string   `json:"infoHex"`
	Envelope    Envelope `json:"envelope"`
	Plaintext   string   `json:"plaintext"` // base64url ohne Füllzeichen
}

func TestVectors(t *testing.T) {
	path := "testdata/vectors.json"
	if *updateVectors {
		privateKey, recipient := testKeyPair(t, 7)
		contentKey := bytes.Repeat([]byte{0xAB}, ContentKeySize)
		sealed, err := SealContentKey(recipient, "mail:konto-1", contentKey)
		if err != nil {
			t.Fatal(err)
		}
		vectors := []vector{{
			Description: "Inhaltsschlüssel für einen Empfänger, Kontext = Eintrags-ID",
			PrivateKey:  base64.RawURLEncoding.EncodeToString(privateKey),
			PublicKey:   base64.RawURLEncoding.EncodeToString(recipient.PublicKey),
			KeyID:       recipient.KeyID,
			Purpose:     PurposeContentKey,
			Context:     "mail:konto-1",
			InfoHex:     bytesToHex(Info(PurposeContentKey, recipient.KeyID, "mail:konto-1")),
			Envelope:    sealed,
			Plaintext:   base64.RawURLEncoding.EncodeToString(contentKey),
		}}
		encoded, _ := json.MarshalIndent(vectors, "", "  ")
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, testVector := range vectors {
		privateKey, _ := base64.RawURLEncoding.DecodeString(testVector.PrivateKey)
		publicKey, _ := base64.RawURLEncoding.DecodeString(testVector.PublicKey)
		if keyID, _ := KeyID(publicKey); keyID != testVector.KeyID {
			t.Fatalf("kid %s, erwartet %s", keyID, testVector.KeyID)
		}
		if bytesToHex(Info(testVector.Purpose, testVector.KeyID, testVector.Context)) != testVector.InfoHex {
			t.Fatal("info weicht ab")
		}
		opened, err := Open(privateKey, testVector.Purpose, testVector.Context, testVector.Envelope)
		if err != nil {
			t.Fatalf("Vektor öffnet nicht: %v", err)
		}
		if base64.RawURLEncoding.EncodeToString(opened) != testVector.Plaintext {
			t.Fatal("Klartext weicht ab")
		}
	}
}

func bytesToHex(raw []byte) string {
	const digits = "0123456789abcdef"
	hexText := make([]byte, 0, len(raw)*2)
	for _, value := range raw {
		hexText = append(hexText, digits[value>>4], digits[value&0x0f])
	}
	return string(hexText)
}
