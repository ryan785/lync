package matcher

import "testing"

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	}
	return 0
}

func TestRpmVercmp(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.1", "1.0", 1},
		{"1.10", "1.9", 1},
		{"1.0", "1.0.0", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"3.0.7-25.el9_2", "3.0.7-25.el9_2", 0},
		{"3.0.7-25.el9_2", "3.0.7-26.el9_2", -1},
		{"3.0.7-25.el9_2", "3.0.7-25.el9_2.1", -1},
		{"2.34-100.el9", "2.34-83.el9_3.7", 1},
	}
	for _, c := range cases {
		got := sign(rpmvercmp(c.a, c.b))
		if got != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSplitNEVR_NonNumericEpochNotEaten(t *testing.T) {
	// "foo:1.0" used to silently parse to epoch=0, version="1.0". With the
	// isAllDigits guard, the "foo:" prefix is kept as part of the version
	// so a downstream comparison failure is visible rather than papered over.
	epoch, version, release := splitNEVR("foo:1.0")
	if epoch != 0 {
		t.Errorf("epoch = %d, want 0", epoch)
	}
	if version != "foo:1.0" {
		t.Errorf("version = %q, want \"foo:1.0\"", version)
	}
	if release != "" {
		t.Errorf("release = %q, want empty", release)
	}
}

func TestCompareNEVR(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0:3.0.7-25.el9_2", "0:3.0.7-26.el9_2", -1},
		{"1:1.0-1.el9", "0:2.0-1.el9", 1},
		{"3.0.7-25", "3.0.7-25", 0},
		{"3.0.7-25.el9_2", "3.0.7-25.el9_2.1", -1},
	}
	for _, c := range cases {
		got := sign(CompareNEVR(c.a, c.b))
		if got != c.want {
			t.Errorf("CompareNEVR(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
