package ipc

type Request struct {
	Cmd  string         `json:"cmd"`
	Args map[string]any `json:"args,omitempty"`
}

type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

const (
	CmdStatus  = "status"
	CmdScan    = "scan"
	CmdSync    = "sync"
	CmdReports = "reports"
	CmdCVE     = "cve"
)
