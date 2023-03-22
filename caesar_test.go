package ctk_test

import (
	"bytes"
	"ctk/basic"
	"ctk/block"
	"ctk/caesar"
	"ctk/ngram"
	"log"
	"testing"
)

func TestCaesarShift(t *testing.T) {
	var key = byte(basic.RandomInt(26))
	log.Printf("enciphering plaintext with key %v", key)
	var ciphertext = caesar.Encipher([]byte(ngram.EnglishPlaintext), []byte{key})
	log.Printf("recovering key from enciphered text...")
	var received = caesar.CaesarShift(ciphertext, ngram.English, ngram.Trigram)
	if key != received {
		t.Fatalf("expected: %d, received: %d", received, key)
	} else {
		log.Printf("expected: %d, received: %d", received, key)
		log.Printf("decrypt sample: %q...", caesar.Decipher(ciphertext[:64], []byte{received}))
	}
}

func TestVigenere(t *testing.T) {
	var keyLength = basic.RandomInt(16) + 16
	var key = basic.RandomBytes(keyLength)
	for i := range key {
		key[i] = key[i] % 26
	}
	log.Printf("enciphering plaintext with key %x", key)
	var ciphertext = caesar.Encipher([]byte(ngram.EnglishPlaintext), key)
	log.Printf("recovering key from enciphered text...")
	var received = caesar.Vigenere([][]byte{ciphertext}, ngram.English, ngram.Trigram)
	if len(key) != len(received) {
		t.Fatalf("expected: %x (%v), recieved: %x (%v)", key, len(key), received, len(received))
	}
	if delta := block.HammingDistance(received, key); !bytes.Equal(received, key) && delta > 5 {
		t.Fatalf("error rate:%d%% (%d), expected: %x (%v), recieved: %x (%v)", delta*100/len(key), delta, key, len(key), received, len(received))
	} else {
		log.Printf("error rate: %d%% (%d), expected: %x (%v), recieved: %x (%v)", delta*100/len(key), delta, key, len(key), received, len(received))
		log.Printf("decrypt sample: %q...", caesar.Decipher(ciphertext[0:64], received))
	}
}
