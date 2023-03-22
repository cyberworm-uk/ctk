package block

import (
	"ctk/basic"
	"ctk/ngram"
	"sort"
)

// XorKeyLength Will use hamming distance to return a managably small set of educated guess at key length.
func XorKeyLength(inputs [][]byte) []int {
	var scores = map[int][]int{}
	var distances = []int{}
	// for a reasonable set of possible key sizes
	// break each input into sized blocks
	// determine the hamming distance between all blocks.
	for sz := 2; sz < 256; sz++ {
		var distance int = 0
		var scale int = 0
		for i := range inputs {
			var blocks = ToBlocks(inputs[i], sz)
			// we compare every block to every other block ... this could probably be reduced.
			for x := range blocks {
				for y := range blocks[x+1:] {
					distance += HammingDistance(blocks[x], blocks[x+1:][y])
					scale += (sz * 8) // largest possible distance
				}
			}
		}
		distance = distance * 2048 / scale
		if _, ok := scores[distance]; !ok {
			distances = append(distances, distance)
		}
		scores[distance] = append(scores[distance], sz)
	}
	// find the smallest distances
	sort.Ints(distances)
	distances = distances[:3]
	// collect the sizes which produced those distances
	var out = []int{}
	for _, d := range distances {
		out = append(out, scores[d]...)
	}
	// find common factors between the sizes
	out = basic.CommonFactors(out)
	return out
}

func XorMultiByte(in []byte, n ngram.Ngram, depth int) []byte {
	var szs = XorKeyLength([][]byte{in})
	var bestScore float64 = 0
	var bestKey []byte
	for _, sz := range szs {
		key := make([]byte, sz)
		rows := ToBlocks(in, sz)
		for i := 0; i < sz; i++ {
			var column = make([]byte, len(rows))
			for r := range rows {
				column[r] = rows[r][i]
			}
			key[i] = basic.XorSingleByte(column, n, ngram.Monogram)
		}
		if score := n.Score(basic.Xor(in, key), depth); score > bestScore {
			bestKey = key
			bestScore = score
		}
	}
	return DedupKey(bestKey)
}
