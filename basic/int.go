package basic

import (
	"math"
	"sort"
)

// MinInt returns the smallest int value between either a or b.
func MinInt(a, b int) int {
	if a > b {
		return b
	}
	return a
}

// MaxInt returns the largest int value between either a or b.
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// GCD returns the greatest common divisor of a and b.
func GCD(a, b int) int {
	for b != 0 {
		t := b
		b = a % b
		a = t
	}
	return a
}

// CommonFactors return a slice of ints comprised only of the smallest, distinct factors of each possible pair of inputs.
func CommonFactors(in []int) []int {
	var inFilter = map[int]bool{}
	for _, a := range in {
		inFilter[a] = true
	}
	in = make([]int, len(inFilter))
	for a := range inFilter {
		in = append(in, a)
	}
	var outFilter = map[int]bool{}
	for i, a := range in {
		for _, b := range in[i:] {
			if g := GCD(a, b); g > 2 && g != a && g != b {
				outFilter[g] = true
			}
		}
	}
	var factors = []int{}
	for factor := range outFilter {
		factors = append(factors, factor)
	}
	return factors
}

func IntStats(in []int) (sum, mean, stdDev int) {
	sum = 0
	for i := range in {
		sum += in[i]
	}
	mean = sum / len(in)
	stdDev = 0
	for i := range in {
		var delta = in[i] - mean
		stdDev += (delta * delta)
	}
	stdDev = int(math.Sqrt(float64(stdDev) / float64(len(in))))
	return
}

func IntFactorial(x int) int {
	var t = 1
	for x > 0 {
		t *= x
		x -= 1
	}
	return t
}

func IntFuzzyFactor(in []int) int {
	var _in = make([]int, len(in))
	copy(_in[:], in[:])
	sort.Ints(_in)
	var bestScore int = 0
	var bestFact int = 0
	for i, a := range _in {
		var score = 0
		for _, b := range _in[i+1:] {
			if b%a == 0 {
				score += a
			}
		}
		if score > bestScore {
			bestScore = score
			bestFact = a
		}
	}
	return bestFact
}
