package ctk_test

import (
	"bytes"
	"crypto/aes"
	"ctk/basic"
	"ctk/block"
	"ctk/ngram"
	"encoding/hex"
	"log"
	"testing"
)

func TestXorMultiByte(t *testing.T) {
	var plaintext = ngram.EnglishPlaintext
	var keyLength = basic.RandomInt(48) + 16
	var key = basic.RandomBytes(keyLength)
	log.Printf("enciphering plaintext with key %x", key)
	var ciphertext = make([]byte, len(plaintext))
	copy(ciphertext, plaintext)
	var blocks = block.ToBlocks(ciphertext, keyLength)
	for i := range blocks {
		copy(blocks[i][0:keyLength], basic.Xor(blocks[i], key))
	}
	log.Printf("recovering key from enciphered text...")
	var received = block.XorMultiByte(ciphertext, ngram.English, ngram.Trigram)
	if len(received) != len(key) {
		t.Errorf("expected: %x (%v), received: %x (%v)", key, len(key), received, len(received))
		return
	}
	var delta = block.HammingDistance(received, key)
	if delta > 5 {
		t.Errorf("key bit errors: %v (%x)", delta, received)
	} else {
		log.Printf("key bit errors: %v (%x)", delta, received)
		log.Printf("decrypt sample: %q...", basic.Xor(ciphertext[:64], received))
	}
}
func TestXorKeyLength(t *testing.T) {
	var plaintext []byte = []byte(ngram.EnglishPlaintext)
	var keyLength = basic.RandomInt(48) + 16
	var key = basic.RandomBytes(keyLength)
	log.Printf("enciphering plaintext with key of length %v", keyLength)
	var ciphertext = make([]byte, len(plaintext))
	copy(ciphertext, plaintext)
	var blocks = block.ToBlocks(ciphertext, keyLength)
	for i := range blocks {
		copy(blocks[i][:], basic.Xor(blocks[i], key))
	}
	log.Printf("recovering key length from enciphered text...")
	var guess = block.XorKeyLength([][]byte{ciphertext})
	var pass = false
	for _, sz := range guess {
		if sz == keyLength {
			log.Printf("expected: %d, received: %d", keyLength, guess)
			pass = true
			break
		}
	}
	if !pass {
		t.Errorf("expected: %d, received: %v", keyLength, guess)
	}
}

func TestHammingDistance(t *testing.T) {
	var a, b = []byte(`this is a test`), []byte(`wokka wokka!!!`)
	var d = block.HammingDistance(a, b)
	if d != 37 {
		t.Errorf("expected: %d, received: %d", 37, d)
	} else {
		log.Printf("expected: %d, received: %d", 37, d)
	}
}

func TestECBDetect(t *testing.T) {
	var ciphertext, _ = hex.DecodeString(`d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a`)
	if !block.ECBDetect(ciphertext, 16) {
		t.Errorf("failed to detect obvious ECB")
	}
}

func TestPKCS7(t *testing.T) {
	var text = []byte(`Hello World.`)
	for sz := byte(1); sz < 0xff; sz++ {
		var pad, e = block.PKCS7Pad(text, sz)
		if e != nil {
			t.Errorf("%s", e)
		}
		var received []byte
		received, e = block.PKCS7Unpad(append(text, pad...))
		if e != nil {
			t.Errorf("%s", e)
		} else if !bytes.Equal(received, text) {
			t.Errorf("invalid result: %q", received)
		}
	}
	if _, e := block.PKCS7Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04")); e != nil {
		t.Errorf("valid padding retuned error: %s", e)
	}
	if _, e := block.PKCS7Unpad([]byte("ICE ICE BABY\x05\x05\x05\x05")); e == nil {
		t.Errorf("invalid apdding returned valid")
	}
	if _, e := block.PKCS7Unpad([]byte("ICE ICE BABY\x01\x02\x03\x04")); e == nil {
		t.Errorf("invalid apdding returned valid")
	}
}

func TestECBByteAtATime(t *testing.T) {
	var key = basic.RandomBytes(32)
	var suffixLen = 16 + basic.RandomInt(48)
	var suffix = basic.RandomBytes(suffixLen)
	var prefixLen = 16 + basic.RandomInt(48)
	var prefix = basic.RandomBytes(prefixLen)
	var maxInputLen = 16 * 2 // (1 + basic.RandomInt(256))
	log.Printf("generated prefix: %x (%v)", prefix, prefixLen)
	log.Printf("generated suffix: %x (%v)", suffix, suffixLen)
	log.Printf("will use AES-ECB key: %x", key)
	log.Printf("setting input length limit to: %v (%v blocks)", maxInputLen, maxInputLen/16)
	var callCount = 0
	blackbox := func(in []byte) []byte {
		if len(in) > maxInputLen {
			return []byte{}
		}
		callCount += 1
		c, _ := aes.NewCipher(key)
		in = append(prefix, in...)
		in = append(in, suffix...)
		pad, _ := block.PKCS7Pad(in, 16)
		in = append(in, pad...)
		var ciphertext = make([]byte, len(in))
		for i, block := range block.ToBlocks(in, 16) {
			c.Encrypt(ciphertext[i*16:(i+1)*16], block[:])
		}
		return ciphertext
	}
	if received, e := block.ECBByteAtATime(blackbox); e != nil {
		t.Errorf("%s", e)
	} else if !bytes.Equal(received, suffix) {
		t.Errorf("expected: %x, received: %x", suffix, received)
	} else {
		log.Printf("expected: %x, received: %x", suffix, received)
	}
	log.Printf("blackbox call count: %v", callCount)
}
