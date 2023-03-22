package caesar

import (
	"bytes"
	"ctk/basic"
	"ctk/block"
	"ctk/ngram"
	"sort"
)

// VigenereKeySize given some slice of byte slices of text enciphered with a Vigenere cipher
// make educated guesses at the probable key size.
func VigenereKeySize(samples [][]byte, n ngram.Ngram, depth int) []int {
	// find the distance between repeated byte sequences in the ciphertext
	// reduce this set down to only the common factors between all distances
	var factors = basic.CommonFactors(block.RepeatDeltas(samples))
	// scores uses the score as a key to store the sizes which returned the scores
	var scores = map[int][]int{}
	// scoreList contains a list of all scores seen, we'll want this so we can sort the scores.
	var scoreList = []int{}
	for sz := 3; sz < 256; sz++ {
		var score = 0
		// avoid division by zero
		var scale = len(factors) + 1
		for _, fact := range factors {
			if fact%sz == 0 {
				// we scale the score by the size.
				// this is because for any given x, x % 3 == 0 is more likely than x % 5 == 0, etc.
				score += sz
			}
		}
		// scale score
		score = score * 10 / scale
		// store it and add it to the list if we haven't seen this score before
		if current, ok := scores[score]; ok {
			scores[score] = append(current, sz)
		} else {
			scores[score] = []int{sz}
			scoreList = append(scoreList, score)
		}
	}
	// sort the scores
	sort.Sort(sort.Reverse(sort.IntSlice(scoreList)))
	// common factors of the two best scored sizes should cover it
	return basic.CommonFactors(append(append([]int{}, scores[scoreList[0]]...), scores[scoreList[1]]...))
}

// Vigenere given some slice of byte slices of text enciphered with a Vigenere cipher
// will attempt to recover the original enciphering key and return the byte slice
// the returned byte-slice will be a slice of shift values.
func Vigenere(samples [][]byte, n ngram.Ngram, depth int) []byte {
	// strip samples to only include cipherable text (I.E. strip punctuation, white space, etc
	var _samples = make([][]byte, len(samples))
	for i := range samples {
		_samples[i] = bytes.Map(alphaOnly, samples[i])
	}
	var bestKey []byte
	var szs = VigenereKeySize(_samples, n, depth)
	var bestScore float64 = 0

	// for each keysize, we score the deciphered text and return the best scoring candidate.
	for _, sz := range szs {
		var key = make([]byte, sz)
		// for each keysize, transponse the inputs into rows of blocks of keysize
		var rows = [][]byte{}
		for j := range _samples {
			rows = append(rows, block.ToBlocks(_samples[j], sz)...)
		}
		// then transpose those rows into columns and process each column as caesar
		// ciphered text, which we can only score with Monogram-depth as our columnar
		// slice will be non-continguous in the original plaintext
		for i := 0; i < sz; i++ {
			var column = make([]byte, len(rows))
			for r := range rows {
				column[r] = rows[r][i]
			}
			key[i] = caesarShift(column, n, ngram.Monogram)
		}
		// once we've recovered the best key value for the keysize
		// we decrypt and score the samples based on our ngram
		var score float64 = 0
		var scale int = 0
		for j := range _samples {
			score += n.Score(decipher(_samples[j], key), depth)
			scale += (len(_samples[j]))
		}
		score = (score * 1000) / float64(scale)
		// the best scoring key value so far determined and updated if required
		if score >= bestScore {
			bestScore = score
			bestKey = key
		}
	}
	// finally we apply our hacky de-duplication to ensure we haven't picked keysize * 2 as the best.
	// if so, it should repeat within our recovered key value and be cleaned up by this process.
	return block.DedupKey(bestKey)
}
