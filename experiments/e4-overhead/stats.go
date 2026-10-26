package main

import (
	"math"
	"slices"
)

// Summary holds the descriptive statistics reported for every metric.
type Summary struct {
	N      int
	Median float64
	P90    float64
	Mean   float64
	Min    float64
	Max    float64
}

// summarize computes n, median, p90 (linear interpolation between closest ranks, the default of
// NumPy/R type 7), mean, min and max. An empty input yields NaN statistics.
func summarize(xs []float64) Summary {
	if len(xs) == 0 {
		nan := math.NaN()
		return Summary{Median: nan, P90: nan, Mean: nan, Min: nan, Max: nan}
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	var sum float64
	for _, x := range s {
		sum += x
	}
	return Summary{
		N:      len(s),
		Median: quantile(s, 0.5),
		P90:    quantile(s, 0.9),
		Mean:   sum / float64(len(s)),
		Min:    s[0],
		Max:    s[len(s)-1],
	}
}

// quantile expects sorted input.
func quantile(sorted []float64, q float64) float64 {
	h := q * float64(len(sorted)-1)
	lo := int(math.Floor(h))
	hi := min(lo+1, len(sorted)-1)
	return sorted[lo] + (h-float64(lo))*(sorted[hi]-sorted[lo])
}
