package basic

import (
	"log"
	"math"
)

func dft(input []float64) ([]float64, []float64) {
	real := make([]float64, len(input))
	imag := make([]float64, len(input))
	arg := -2.0 * math.Pi / float64(len(input))
	for k := 0; k < len(input); k++ {
		r, i := 0.0, 0.0
		for n := 0; n < len(input); n++ {
			r += input[n] * math.Cos(arg*float64(n)*float64(k))
			i += input[n] * math.Sin(arg*float64(n)*float64(k))
		}
		real[k], imag[k] = r, i
	}
	return real, imag
}

func amplitude(real, imag []float64) []float64 {
	amp := make([]float64, len(real))
	for i := 0; i < len(real); i++ {
		amp[i] = math.Sqrt(real[i]*real[i] + imag[i]*imag[i])
	}
	return amp
}

func float64Stats(inputs []float64) (sum, mean, stdDev float64) {
	sum, mean, stdDev = 0, 0, 0
	var scale = float64(len(inputs))
	for _, i := range inputs {
		sum += i
	}
	mean = sum / scale
	for _, i := range inputs {
		stdDev += (i - mean) * (i - mean)
	}
	stdDev = math.Sqrt(stdDev / scale)
	return sum, mean, stdDev
}

func FactorFinder(inputs []int) {
	var conv = make([]float64, len(inputs))
	for i := range conv {
		conv[i] = float64(inputs[i])
	}
	real, imag := dft(conv)
	amp := amplitude(real, imag)
	var sum, mean, stdDev = float64Stats(amp)
	log.Printf("sum: %v, mean: %v, stdDev: %v", sum, mean, stdDev)
	for key, value := range amp {
		log.Printf("key: %v,\tdeviations: %v", key, (value-mean)/stdDev)
	}
}
