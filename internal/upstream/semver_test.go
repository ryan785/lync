package upstream

import "testing"

func TestParseVersion(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"v22.23.4", "22.23.4", true},
		{"24.22.1", "24.22.1", true},
		{" v0.10.48\n", "0.10.48", true},
		{"22.23", "", false},
		{"v22.x.1", "", false},
		{"", "", false},
		{"22.23.4.5", "", false},
	} {
		v, ok := ParseVersion(c.in)
		if ok != c.ok || (ok && v.String() != c.want) {
			t.Errorf("ParseVersion(%q) = %v, %v; want %s, %v", c.in, v, ok, c.want, c.ok)
		}
	}
}

func TestRangeSatisfies(t *testing.T) {
	cases := []struct {
		rng  string
		in   []string
		out  []string
		fail bool
	}{
		{rng: "*", in: []string{"0.0.1", "26.12.1"}},
		{rng: "", out: []string{"22.0.0"}},
		{rng: "22.x", in: []string{"22.0.0", "22.99.99"}, out: []string{"21.9.9", "23.0.0"}},
		{rng: "22", in: []string{"22.4.1"}, out: []string{"23.0.0"}},
		{rng: "22.1.x", in: []string{"22.1.0", "22.1.9"}, out: []string{"22.2.0", "22.0.9"}},
		{rng: "22.x || 24.x || 26.x", in: []string{"22.22.0", "24.0.0", "26.12.1"}, out: []string{"20.18.0", "25.1.0"}},
		{rng: "^22.23.4 || ^24.22.1 || ^26.12.1",
			in:  []string{"22.23.4", "22.30.0", "24.22.1", "26.12.1", "26.13.0"},
			out: []string{"22.23.3", "22.22.0", "24.22.0", "26.12.0", "23.0.0", "25.9.0"}},
		{rng: "<22.23.4 || >=24.0.0 <24.22.1", in: []string{"22.23.3", "20.0.0", "24.0.0", "24.22.0"}, out: []string{"22.23.4", "23.0.0", "24.22.1", "26.0.0"}},
		{rng: ">=6.0.0 <6.2.0 || 5.x || 4.x", in: []string{"6.1.9", "5.0.0", "4.9.1"}, out: []string{"6.2.0", "3.9.9", "7.0.0"}},
		{rng: "<= 10", in: []string{"10.99.0", "8.0.0"}, out: []string{"11.0.0"}},
		{rng: "<=10.2", in: []string{"10.2.9"}, out: []string{"10.3.0"}},
		{rng: "<= 10.2.3", in: []string{"10.2.3"}, out: []string{"10.2.4"}},
		{rng: ">22", in: []string{"23.0.0"}, out: []string{"22.99.0"}},
		{rng: "> 22.1.0", in: []string{"22.1.1"}, out: []string{"22.1.0"}},
		{rng: "<22", in: []string{"21.99.99"}, out: []string{"22.0.0"}},
		{rng: "=22.1.0", in: []string{"22.1.0"}, out: []string{"22.1.1"}},
		{rng: "v22.1.0", in: []string{"22.1.0"}, out: []string{"22.1.1"}},
		{rng: "~22.1.3", in: []string{"22.1.3", "22.1.9"}, out: []string{"22.2.0", "22.1.2"}},
		{rng: "~22", in: []string{"22.9.0"}, out: []string{"23.0.0"}},
		{rng: "^0.10.2", in: []string{"0.10.9"}, out: []string{"0.11.0", "0.10.1"}},
		{rng: "^0.0.3", in: []string{"0.0.3"}, out: []string{"0.0.4"}},
		{rng: "^22", in: []string{"22.0.0", "22.5.1"}, out: []string{"23.0.0"}},
		{rng: "18.0.0 - 18.2", in: []string{"18.0.0", "18.2.9"}, out: []string{"18.3.0"}},
		{rng: "18.0.0 - 18.2.3", in: []string{"18.2.3"}, out: []string{"18.2.4"}},
		{rng: "8.x || 7.x || 4.x || 6.x || 5.x", in: []string{"4.8.3", "8.1.3"}, out: []string{"9.0.0", "3.0.0"}},
		{rng: ">=22.x", fail: false, in: []string{"22.0.0", "30.0.0"}, out: []string{"21.0.0"}},
		{rng: "22.a", fail: true},
		{rng: ">=1.2.3.4", fail: true},
	}
	for _, c := range cases {
		r, err := ParseRange(c.rng)
		if c.fail {
			if err == nil {
				t.Errorf("ParseRange(%q): expected an error", c.rng)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRange(%q): %v", c.rng, err)
			continue
		}
		for _, s := range c.in {
			v, _ := ParseVersion(s)
			if !r.Satisfies(v) {
				t.Errorf("%q should include %s", c.rng, s)
			}
		}
		for _, s := range c.out {
			v, _ := ParseVersion(s)
			if r.Satisfies(v) {
				t.Errorf("%q should exclude %s", c.rng, s)
			}
		}
	}
}

func TestRangeLowestAbove(t *testing.T) {
	r, err := ParseRange("^22.23.4 || ^24.22.1 || ^26.12.1 || >=22.24.0 <23")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		major int
		v     string
		want  string
	}{
		{22, "22.22.0", "22.23.4"},
		{24, "24.0.0", "24.22.1"},
		{26, "26.12.0", "26.12.1"},
		{22, "22.23.4", "22.24.0"},
		{20, "20.1.0", ""},
		{26, "26.12.1", ""},
	} {
		v, _ := ParseVersion(c.v)
		got, ok := r.LowestAbove(c.major, v)
		if (c.want == "") == ok || (ok && got.String() != c.want) {
			t.Errorf("LowestAbove(%d, %s) = %v, %v; want %q", c.major, c.v, got, ok, c.want)
		}
	}
	if fs := r.FixesOnMajor(22); len(fs) != 2 || fs[0].String() != "22.23.4" {
		t.Errorf("FixesOnMajor(22) = %v", fs)
	}
}
