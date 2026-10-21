package feed

import (
	"math"
	"strings"
)

// CVSS3BaseScore computes the CVSS v3.0/v3.1 base score from a vector
// string ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8). OSV
// records carry vectors rather than scores, so without this every Debian
// and Alpine finding would show as Unknown severity. Returns ok=false for
// anything that is not a complete v3 vector.
func CVSS3BaseScore(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	m := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		k, v, ok := strings.Cut(part, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	val := map[string]float64{}
	for k, table := range weights {
		w, ok := table[m[k]]
		if !ok {
			return 0, false
		}
		val[k] = w
	}
	scope := m["S"]
	if scope != "U" && scope != "C" {
		return 0, false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scope == "C" {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scope == "C" {
			pr = 0.5
		}
	default:
		return 0, false
	}
	iss := 1 - (1-val["C"])*(1-val["I"])*(1-val["A"])
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * val["AV"] * val["AC"] * pr * val["UI"]
	if scope == "U" {
		return roundUp(math.Min(impact+expl, 10)), true
	}
	return roundUp(math.Min(1.08*(impact+expl), 10)), true
}

// roundUp is the CVSS v3.1 "Roundup": smallest one-decimal number >= x,
// computed on integers to avoid float artefacts (4.000000001 -> 4.0).
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// SeverityFromCVSS maps a CVSS v3 base score to the qualitative rating.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	}
	return ""
}
