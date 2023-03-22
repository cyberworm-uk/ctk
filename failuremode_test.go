package ctk_test

import (
	"bytes"
	"ctk/caesar"
	"ctk/ngram"
	"testing"
)

// these are cases I encounter where tests with randomized variables fail, to allow further diagnosis

func TestFailureCase1(t *testing.T) {
	var key = []byte{0x13, 0x05, 0x0c, 0x18, 0x18, 0x01, 0x00, 0x02, 0x13, 0x09, 0x0d, 0x05, 0x14, 0x0e, 0x0e, 0x01, 0x09, 0x14, 0x16, 0x17, 0x00, 0x11, 0x04}
	var ciphertext = caesar.Encipher([]byte(ngram.EnglishPlaintext), key)
	var received = caesar.Vigenere([][]byte{ciphertext}, ngram.English, ngram.Trigram)
	if !bytes.Equal(received, key) {
		t.Errorf("expected: %x, received: %x", key, received)
	}
}
