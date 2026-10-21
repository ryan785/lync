package collector

import (
	"context"
	"github.com/ryan785/lync/internal/audit"
	"strings"
	"time"
)

func readKernel() (KernelInfo, error) {
	k := KernelInfo{}
	get := func(arg string) string {
		out, err := audit.Output(context.Background(), 10*time.Second, "uname", arg)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	k.Release = get("-r")
	k.Version = get("-v")
	k.Machine = get("-m")
	return k, nil
}
