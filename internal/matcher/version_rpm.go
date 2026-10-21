package matcher

import (
	"strconv"
	"strings"
)

// rpmvercmp compares two RPM version (or release) strings using the
// canonical algorithm from rpm-software-management/rpm. Returns -1, 0, +1.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	for one < len(a) || two < len(b) {
		for one < len(a) && !isAlnum(a[one]) && a[one] != '~' {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) && b[two] != '~' {
			two++
		}

		aTilde := one < len(a) && a[one] == '~'
		bTilde := two < len(b) && b[two] == '~'
		if aTilde || bTilde {
			if !aTilde {
				return 1
			}
			if !bTilde {
				return -1
			}
			one++
			two++
			continue
		}

		if one >= len(a) || two >= len(b) {
			break
		}

		var isNum bool
		aEnd, bEnd := one, two
		if isDigit(a[one]) {
			isNum = true
			for aEnd < len(a) && isDigit(a[aEnd]) {
				aEnd++
			}
			for bEnd < len(b) && isDigit(b[bEnd]) {
				bEnd++
			}
		} else {
			for aEnd < len(a) && isAlpha(a[aEnd]) {
				aEnd++
			}
			for bEnd < len(b) && isAlpha(b[bEnd]) {
				bEnd++
			}
		}

		if bEnd == two {
			if isNum {
				return 1
			}
			return -1
		}

		aSeg, bSeg := a[one:aEnd], b[two:bEnd]
		if isNum {
			aTrim := strings.TrimLeft(aSeg, "0")
			bTrim := strings.TrimLeft(bSeg, "0")
			if len(aTrim) > len(bTrim) {
				return 1
			}
			if len(bTrim) > len(aTrim) {
				return -1
			}
			if aTrim < bTrim {
				return -1
			}
			if aTrim > bTrim {
				return 1
			}
		} else {
			if aSeg < bSeg {
				return -1
			}
			if aSeg > bSeg {
				return 1
			}
		}
		one = aEnd
		two = bEnd
	}
	if one >= len(a) && two >= len(b) {
		return 0
	}
	if one >= len(a) {
		return -1
	}
	return 1
}

// CompareNEVR compares two NEVR strings of form "[epoch:]version[-release]".
func CompareNEVR(a, b string) int {
	aE, aV, aR := splitNEVR(a)
	bE, bV, bR := splitNEVR(b)
	if aE != bE {
		if aE < bE {
			return -1
		}
		return 1
	}
	if c := rpmvercmp(aV, bV); c != 0 {
		return c
	}
	return rpmvercmp(aR, bR)
}

func splitNEVR(s string) (epoch int, version, release string) {
	// Epoch parsing accepts "<digits>:" only. A non-numeric prefix like
	// "foo:1.0" must NOT silently become epoch=0; we leave the colon in
	// the version part so a downstream mismatch is visible rather than
	// hidden under a fake epoch.
	if i := strings.Index(s, ":"); i > 0 && i < 5 {
		if isAllDigits(s[:i]) {
			if v, err := strconv.Atoi(s[:i]); err == nil {
				epoch = v
				s = s[i+1:]
			}
		}
	}
	if i := strings.LastIndex(s, "-"); i > 0 {
		version = s[:i]
		release = s[i+1:]
	} else {
		version = s
	}
	return
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
func isAlnum(b byte) bool { return isDigit(b) || isAlpha(b) }
