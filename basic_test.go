package ctk_test

import (
	"bytes"
	"ctk/basic"
	"ctk/ngram"
	"log"
	"testing"
)

func TestXorSingleByte(t *testing.T) {
	var plaintext = []byte(ngram.EnglishPlaintext)
	var key = basic.RandomBytes(1)
	log.Printf("enciphering plaintext with key %v", key[0])
	var ciphertext = basic.Xor(plaintext, key)
	log.Printf("recovering key from enciphered text...")
	var keyGuess = basic.XorSingleByte(ciphertext, ngram.English, 3)
	if keyGuess != key[0] {
		t.Errorf("expected: %v, received: %v", key[0], keyGuess)
	} else {
		log.Printf("expected: %v, received: %v", key[0], keyGuess)
	}
}

func TestXor(t *testing.T) {
	var a = []byte(`Lorem ipsum dolor sit amet`)
	var b = basic.RandomBytes(len(a))
	var c = basic.Xor(a, b)
	var d = basic.Xor(c, b)
	if bytes.Equal(b, c) {
		t.Errorf("Xor performed incorrectly.")
	}
	if !bytes.Equal(a, d) {
		t.Errorf("Xor performed incorrectly.")
	}
}
