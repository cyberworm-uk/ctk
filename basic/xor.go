package basic

import (
	"ctk/ngram"
)

// Xor will iterate over in, and xor it with the corresponding value from key.
// the offset into key will repeat as required by the length of in.
func Xor(in, key []byte) []byte {
	var x = make([]byte, len(in))
	for i := range x {
		x[i] = in[i] ^ key[i%len(key)]
	}
	return x
}

// XorSingleByte given some byte slice, in, which has been xor'd with a single byte key
//  and an ngram model to score possible plaintexts will return the best scoring byte key.
func XorSingleByte(in []byte, n ngram.Ngram, depth int) byte {
	var bestScore float64 = 0
	var bestKey byte
	// for every possible key, produce a resulting candidate decryption and score it.
	// return the key associated with the best score observed of all candidates.
	for k := 0; k < 256; k++ {
		if score := n.Score(Xor(in, []byte{byte(k)}), depth); score > bestScore {
			bestKey = byte(k)
			bestScore = score
		}
	}
	// return the best scoring key seen
	return bestKey
}
