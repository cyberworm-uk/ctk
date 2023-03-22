package block

import (
	"bytes"
	"ctk/basic"
)

// ECBDetect will attempt to determine if ciphertext is ECB mode.
// Returns true if ECB, otherwise
// This is essentially just a check for repeat blocks, as such:
// A false result should really be considered "undetermined but no reason to suspect it".
// A true result should really be considered "high probability".
func ECBDetect(ciphertext []byte, blocksize int) bool {
	for _, block := range ToBlocks(ciphertext, blocksize) {
		if bytes.Count(ciphertext, block) > 1 {
			return true
		}
	}
	return false
}

func ECBByteAtATime(blackbox func([]byte) []byte) ([]byte, error) {
	// discover the blocksize of the underlying cipher.
	// encrypt an increasing sized block until the output size increases.
	// the padding scheme will normally require it to add exactly 1 full block of additional data at each block number increase.
	var pad = []byte{'K'}
	var reference = blackbox(pad)
	var sample = reference
	for len(reference) == len(sample) {
		pad = append(pad, 'K')
		sample = blackbox(pad)
	}
	if len(reference) > len(sample) {
		return nil, ErrBlock
	}
	var blocksize = len(sample) - len(reference)
	//var additional = len(sample) - blocksize - len(pad)
	//var ePad = sample[len(sample)-blocksize:] // this is a full block of padding, encrypted. we could determine the padding scheme.
	var align, offset, suffix int
	// now that we know that the larget number of consecutive repeat blocks is n
	// we'll create at least n+1 blocks of our marker, then pad it with each possible size and run it through the blackbox.
	// once we see n+1 repeat blocks in the output, we know we're aligned with a block boundary.
	// we'll also take note of the offset of our input in the output, and figure out how long the suffix and prefix are.
	for align = blocksize - 1; align >= 0; align-- {
		alignBytes := bytes.Repeat([]byte{'K'}, align)
		a := ToBlocks(blackbox(append(alignBytes, '0')), blocksize)
		b := ToBlocks(blackbox(append(alignBytes, '1')), blocksize)
		if len(a) != len(b) {
			return nil, ErrBlock
		}
	}
	var maxBlocks = 1
	for ; maxBlocks <= 256; maxBlocks++ {
		if len(blackbox(basic.RandomBytes(align+(blocksize*maxBlocks)))) < align+(blocksize*maxBlocks) {
			maxBlocks -= 1
			break
		}
	}
	var alignBytes = bytes.Repeat([]byte{'K'}, align)     // blocks to take us to the block boundary
	var guessBlock = bytes.Repeat([]byte{'K'}, blocksize) // hold the known bytes of our guess.
	var suffixBytes = []byte{}                            // accumulate known suffix bytes as we receive them.
	batchBlackbox := func(in [][]byte) [][]byte {
		var out = [][]byte{}
		for i := 0; i < len(in); i += maxBlocks {
			var batch = append([]byte{}, alignBytes...)
			var batchLen = 0
			for _, block := range in[i:basic.MinInt(i+maxBlocks, len(in))] {
				batch = append(batch, block...)
				batchLen++
			}
			var results = ToBlocks(blackbox(batch), blocksize)
			out = append(out, results[offset:offset+batchLen]...)
		}
		return out
	}
	for b := 0; len(suffixBytes) < suffix; b++ {
		var nextBlock = []byte{}
		for i := 0; i < blocksize && (b*blocksize)+i < suffix; i++ {
			var guess = append([]byte{}, alignBytes...)
			guess = append(guess, guessBlock[1+i:]...)
			var truth = ToBlocks(blackbox(guess), blocksize)[offset+b]
			var blocks = [][]byte{}
			for _p := 0; _p < 256; _p++ {
				var p = byte(_p)
				var block = append([]byte{}, guessBlock[1+i:]...)
				block = append(block, append(nextBlock, p)...)
				blocks = append(blocks, block)
			}
			blocks = batchBlackbox(blocks)
			for i, block := range blocks {
				if bytes.Equal(block, truth) {
					nextBlock = append(nextBlock, byte(i))
					break
				}
			}
			if len(nextBlock) == i {
				return nil, ErrBlock
			}
		}
		guessBlock = nextBlock
		suffixBytes = append(suffixBytes, nextBlock...)
	}
	return suffixBytes, nil
}
