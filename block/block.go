package block

import (
	"bytes"
	"errors"
	"math/bits"
	"sort"
)

var ErrPadding = errors.New("bad padding")
var ErrBlock = errors.New("bad block size")
var ErrMode = errors.New("bad block cipher mode")

// PKCS&Pad given some byte slice, in, and a desired block size, will produce the associated PKCS7 Padding.
func PKCS7Pad(in []byte, size byte) ([]byte, error) {
	if size == 0 {
		return []byte{}, ErrBlock
	}
	var padLength = int(size) - (len(in) % int(size))
	if padLength == 0 {
		padLength = int(size)
	}
	return bytes.Repeat([]byte{byte(padLength)}, int(padLength)), nil
}

// PKCS7Unpad
func PKCS7Unpad(in []byte) ([]byte, error) {
	if padLength := in[len(in)-1]; int(padLength) > len(in) || padLength == 0 || !bytes.Equal(bytes.Repeat([]byte{padLength}, int(padLength)), in[len(in)-int(padLength):]) {
		return []byte{}, ErrPadding
	} else {
		return in[:len(in)-int(padLength)], nil
	}
}

// HammingDistance given two equal length byte slices
// will return the number of differing bits.
func HammingDistance(a, b []byte) int {
	if len(b) != len(a) {
		panic("length mismatch")
	}
	var out int = 0
	for i := range a {
		out += bits.OnesCount8(a[i] ^ b[i])
	}
	return out
}

// Given an input byte slice, and a size, breaks the input into slices of given size and returns the result.
// Additional bytes beyond the last block boundary that are not large enough to form a block of the given
// size are discarded.
func ToBlocks(input []byte, size int) [][]byte {
	if len(input) < size {
		return [][]byte{}
	}
	var out = make([][]byte, len(input)/size)
	for i := 0; i < len(out); i++ {
		out[i] = input[i*size : (i+1)*size]
	}
	return out
}

// Given a bytes slice slice of aligned ciphertexts encrypted with the same
// repeating key pattern, find the distances between repeated byte patterns
// in the ciphertexts.
// The intuition is that repeats of bytes in ciphertexts encrypted with repeating
// keys are where patterns in the underlying plaintext and key co-incide. As such
// the distance between them will tend to be a factor of the key length.
func RepeatDeltas(inputs [][]byte) []int {
	var out = map[int]bool{}
	for repeatLen := 3; repeatLen < 256; repeatLen++ {
		var blocks = map[string][]int{}
		for i := range inputs {
			for o, b := range ToBlocks(inputs[i][:], repeatLen) {
				blocks[string(b)] = append(blocks[string(b)], o*repeatLen)
			}
		}
		for _, offsets := range blocks {
			for i, a := range offsets {
				for _, b := range offsets[i+1:] {
					var delta = a - b
					if delta < 0 {
						delta *= -1
					}
					if delta > 0 {
						out[delta] = true
					}
				}
			}
		}
	}
	var deltas = []int{}
	for delta := range out {
		deltas = append(deltas, delta)
	}
	sort.Ints(deltas)
	return deltas
}

// DedupKey is a bit of a hack but it does the job.
// When unsure of key size, multiples of the true key size will score equivalently.
// This ensures that we return the most concise key value.
func DedupKey(k []byte) []byte {
	var out = k[:]
	for i := 2; i < len(k)/2; i++ {
		if len(k)%i == 0 {
			if bytes.Equal(k[0:len(k)/i], k[len(k)/i:(len(k)/i)*2]) {
				out = k[0 : len(k)/i]
			}
		}
	}
	return out
}
