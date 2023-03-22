package basic

import (
	"crypto/rand"
	"math/big"
)

// Bytes returns a byte slice of size sz populated by random bytes.
func RandomBytes(size int) []byte {
	var blob = make([]byte, size)
	if _, e := rand.Read(blob[:]); e != nil {
		panic(e)
	}
	return blob
}

// Int returns a random positive integer with a value up to and excluding maxint
func RandomInt(max int) int {
	var _max = big.NewInt(int64(max))
	var r *big.Int
	var e error
	r, e = rand.Int(rand.Reader, _max)
	if e != nil {
		panic(e)
	}
	return int(r.Int64())
}
