package caesar

import (
	"bytes"
	"ctk/ngram"
)

// alphaOnly returns the alphabet offset of r
// otherwise returns -1
// eg. 'A1B.C%D!' => '\x00\x01\x02\x03'
func alphaOnly(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 'a'
	} else if r >= 'A' && r <= 'Z' {
		return r - 'A'
	} else {
		return -1
	}
}

func CaesarShift(text []byte, n ngram.Ngram, depth int) byte {
	return caesarShift(bytes.Map(alphaOnly, text), ngram.English, depth)
}

// CaesarShift given some Caesar Shifted English text as input, will return the guessed shift key.
func caesarShift(text []byte, n ngram.Ngram, depth int) byte {
	//text = text[:basic.MinInt(len(text), 1024)]
	var bestScore float64 = 0
	var bestKey byte = 0
	for k := byte(0); k < 26; k++ {
		var decrypt = decipher(text, []byte{k})
		if s := n.Score(decrypt, depth); s > bestScore {
			bestScore = s
			bestKey = k
		}
	}
	return bestKey
}
