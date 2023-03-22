package caesar

// internal use only (expects '\x00\x01\x03\x04' rather than 'abcd')
func decipher(in []byte, k []byte) []byte {
	var out = make([]byte, len(in))
	for i := range in {
		out[i] = ((in[i] + (26 - k[i%len(k)])) % 26) + 'a'
	}
	return out
}

// Decipher given some byte slice in of text, encipher it with vigenere using key k
// will return the resulting ciphertext.
// For caesar shifts, use a single byte slice.
func Encipher(in []byte, k []byte) []byte {
	var out = make([]byte, len(in))
	var state = 0
	for i := range in {
		if in[i] >= 'A' && in[i] <= 'Z' {
			out[i] = (((in[i] - 'A') + (k[state%len(k)])) % 26) + 'A'
			state += 1
		} else if in[i] >= 'a' && in[i] <= 'z' {
			out[i] = (((in[i] - 'a') + (k[state%len(k)])) % 26) + 'a'
			state += 1
		} else {
			out[i] = in[i]
		}
	}
	return out
}

// Decipher given some byte slice in of text enciphered with a vignere with key k
// will return the deciphered text using key k.
// For caesar shifts, use a single byte slice.
func Decipher(in []byte, k []byte) []byte {
	var out = make([]byte, len(in))
	var state = 0
	for i := range in {
		if in[i] >= 'A' && in[i] <= 'Z' {
			out[i] = (((in[i] - 'A') + (26 - k[state%len(k)])) % 26) + 'A'
			state += 1
		} else if in[i] >= 'a' && in[i] <= 'z' {
			out[i] = (((in[i] - 'a') + (26 - k[state%len(k)])) % 26) + 'a'
			state += 1
		} else {
			out[i] = in[i]
		}
	}
	return out
}
