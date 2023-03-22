package ngram

const (
	Monogram = iota + 1
	Bigram
	Trigram
)

type Ngram interface {
	Score(text []byte, depth int) float64
}
