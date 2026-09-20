package engine

import "math/bits"

// The score includes collisions in the filter's five-bit lookahead.
func fdrBucketCost(literals []fdrLiteral) float64 {
	if len(literals) == 0 {
		return 0
	}
	var allowed [8][256]uint32
	minimum := 8
	for _, literal := range literals {
		minimum = min(minimum, len(literal.masks))
		for position := 0; position < min(8, len(literal.masks)); position++ {
			next := ^uint32(0)
			if position > 0 {
				next = 0
				for word, mask := range literal.masks[len(literal.masks)-position] {
					for mask != 0 {
						value := word*64 + bits.TrailingZeros64(mask)
						next |= uint32(1) << (value & 31)
						mask &= mask - 1
					}
				}
			}
			for word, mask := range literal.masks[len(literal.masks)-1-position] {
				for mask != 0 {
					value := word*64 + bits.TrailingZeros64(mask)
					allowed[position][value] |= next
					mask &= mask - 1
				}
			}
		}
	}
	var distribution [32]float64
	var weights [256]float64
	var total float64
	for value := range weights {
		total += float64(literalByteWeight(lowerASCII(byte(value))))
	}
	for value := range weights {
		weights[value] = float64(literalByteWeight(lowerASCII(byte(value)))) / total
		if allowed[0][value] != 0 {
			distribution[value&31] += weights[value]
		}
	}
	for position := 1; position < minimum; position++ {
		var next [32]float64
		for value, mask := range allowed[position] {
			var probability float64
			for mask != 0 {
				probability += distribution[bits.TrailingZeros32(mask)]
				mask &= mask - 1
			}
			next[value&31] += weights[value] * probability
		}
		distribution = next
	}
	var score float64
	for _, probability := range distribution {
		score += probability
	}
	return score
}

func optimizeFDRBuckets(groups [][]fdrLiteral) [][]fdrLiteral {
	costs := make([]float64, len(groups))
	for i := range groups {
		groups[i] = append([]fdrLiteral(nil), groups[i]...)
		costs[i] = fdrBucketCost(groups[i])
	}
	for pass := 0; pass < 4; pass++ {
		moves := 0
		for from := range groups {
			for index := 0; index < len(groups[from]); index++ {
				literal := groups[from][index]
				without := append([]fdrLiteral(nil), groups[from][:index]...)
				without = append(without, groups[from][index+1:]...)
				reduced := fdrBucketCost(without)
				best, delta, bestCost := from, float64(0), float64(0)
				for to := range groups {
					if to == from {
						continue
					}
					increased := fdrBucketCost(append(groups[to], literal))
					change := reduced + increased - costs[from] - costs[to]
					if change < delta-1e-18 {
						best, delta, bestCost = to, change, increased
					}
				}
				if best == from {
					continue
				}
				groups[from], costs[from] = without, reduced
				groups[best], costs[best] = append(groups[best], literal), bestCost
				moves++
				index--
			}
		}
		if moves == 0 {
			break
		}
	}
	return groups
}
