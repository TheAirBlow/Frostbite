// Package link defines the messages exchanged between the panel and its daemons.
package link

import (
	"encoding/json"
	"fmt"
	"time"

	"frostbite/internal/spec"
)

// Message types.
const (
	TypeHello   = "hello"   // agent -> panel, first message after connecting
	TypeSpec    = "spec"    // panel -> agent, desired state
	TypeAck     = "ack"     // agent -> panel, result of applying a spec
	TypeStats   = "stats"   // agent -> panel, usage since the last report
	TypeMetrics = "metrics" // agent -> panel, host health
	TypeCmd     = "cmd"     // panel -> agent
	TypeResult  = "result"  // agent -> panel, answer to a cmd
	TypeCerts   = "certs"   // agent -> panel, state of automatic certificates
)

// Path is where agents connect on the panel.
const Path = "/api/link"

// Message is the envelope every frame uses.
type Message struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body,omitempty"`
}

// Encode wraps body in an envelope.
func Encode(typ string, body any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Message{Type: typ, Body: raw})
}

// Decode splits an envelope.
func Decode(data []byte) (Message, error) {
	var m Message
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("bad frame: %w", err)
	}
	return m, nil
}

// Hello introduces an agent.
type Hello struct {
	Kind       string   `json:"kind"`
	AgentVer   string   `json:"agent_version"`
	CoreVer    string   `json:"core_version"`
	AppliedRev int64    `json:"applied_rev"`
	Host       HostInfo `json:"host"`
}

// HostInfo describes the machine an agent runs on.
type HostInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	CPUs     int    `json:"cpus"`
	MemTotal uint64 `json:"mem_total"`
	Kernel   string `json:"kernel"`
}

// Spec carries the desired state of a daemon.
type Spec struct {
	Revision int64       `json:"revision"`
	Daemon   spec.Daemon `json:"daemon"`
}

// Ack reports whether a revision was applied.
type Ack struct {
	Revision int64  `json:"revision"`
	Error    string `json:"error,omitempty"`
}

// Usage is traffic in bytes since the previous report.
type Usage struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Stats is a usage report keyed by user label.
type Stats struct {
	Users  map[string]Usage    `json:"users"`
	Online map[string][]string `json:"online,omitempty"` // user label -> source ips
}

// Metrics is a host health sample.
type Metrics struct {
	CPU       float64 `json:"cpu"` // percent
	MemUsed   uint64  `json:"mem_used"`
	MemTotal  uint64  `json:"mem_total"`
	DiskUsed  uint64  `json:"disk_used"`
	DiskTotal uint64  `json:"disk_total"`
	NetUp     uint64  `json:"net_up"`   // bytes per second
	NetDown   uint64  `json:"net_down"` // bytes per second
	Load1     float64 `json:"load1"`
	Uptime    uint64  `json:"uptime"`

	// Added later, older daemons leave them at zero.
	Load5          float64 `json:"load5,omitempty"`
	Load15         float64 `json:"load15,omitempty"`
	SwapUsed       uint64  `json:"swap_used,omitempty"`
	SwapTotal      uint64  `json:"swap_total,omitempty"`
	DiskRead       uint64  `json:"disk_read,omitempty"`  // bytes per second
	DiskWrite      uint64  `json:"disk_write,omitempty"` // bytes per second
	NetUpPackets   uint64  `json:"net_up_packets,omitempty"`
	NetDownPackets uint64  `json:"net_down_packets,omitempty"`
	NetErrors      uint64  `json:"net_errors,omitempty"` // errors and drops per second
	TCPEstablished uint64  `json:"tcp_established,omitempty"`
	TCPInUse       uint64  `json:"tcp_inuse,omitempty"`
	TCPTimeWait    uint64  `json:"tcp_time_wait,omitempty"`
	UDPInUse       uint64  `json:"udp_inuse,omitempty"`
	OpenFiles      uint64  `json:"open_files,omitempty"`
	MaxOpenFiles   uint64  `json:"max_open_files,omitempty"`
	Processes      uint64  `json:"processes,omitempty"`

	AgentGoroutines int    `json:"agent_goroutines,omitempty"`
	AgentHeap       uint64 `json:"agent_heap,omitempty"`
	AgentUptime     uint64 `json:"agent_uptime,omitempty"` // seconds
}

// Commands the panel can send.
const (
	CmdRestart     = "restart"
	CmdLogs        = "logs"
	CmdTestReality = "test_reality"
	CmdTestHost    = "test_host"
)

// Cmd asks an agent to do something right now.
type Cmd struct {
	ID   int64             `json:"id"`
	Name string            `json:"name"`
	Args map[string]string `json:"args,omitempty"`
}

// Result answers a Cmd.
type Result struct {
	ID     int64  `json:"id"`
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// CertStatus reports one automatic certificate.
type CertStatus struct {
	Domain      string    `json:"domain"`
	OK          bool      `json:"ok"`
	Placeholder bool      `json:"placeholder"` // a self signed stand-in is serving until the real one arrives
	Error       string    `json:"error,omitempty"`
	Expires     time.Time `json:"expires"`
}
