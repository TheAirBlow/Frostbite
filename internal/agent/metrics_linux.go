package agent

import (
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"frostbite/internal/link"
)

// agentStart is when this process began, for the agent uptime.
var agentStart = time.Now()

// sampler turns counters in /proc into rates between calls.
type sampler struct {
	idle, total uint64
	net         netCounters
	disk        diskCounters
	at          time.Time
}

type netCounters struct{ rx, tx, rxPkts, txPkts, errs uint64 }

type diskCounters struct{ read, written uint64 }

// newSampler primes a sampler.
func newSampler() *sampler {
	s := &sampler{at: time.Now()}
	s.idle, s.total = readCPU()
	s.net = readNet()
	s.disk = readDisk()
	return s
}

// perSecond turns a counter difference into a rate, treating a counter that went backwards as a reset.
func perSecond(now, before uint64, secs float64) uint64 {
	if now < before || secs <= 0 {
		return 0
	}
	return uint64(float64(now-before) / secs)
}

// sample reads the current host health.
func (s *sampler) sample() link.Metrics {
	m := link.Metrics{}
	now := time.Now()
	secs := now.Sub(s.at).Seconds()
	s.at = now

	idle, total := readCPU()
	if dt := total - s.total; dt > 0 {
		m.CPU = 100 * float64(dt-(idle-s.idle)) / float64(dt)
	}
	s.idle, s.total = idle, total

	n := readNet()
	m.NetDown, m.NetUp = perSecond(n.rx, s.net.rx, secs), perSecond(n.tx, s.net.tx, secs)
	m.NetDownPackets, m.NetUpPackets = perSecond(n.rxPkts, s.net.rxPkts, secs), perSecond(n.txPkts, s.net.txPkts, secs)
	m.NetErrors = perSecond(n.errs, s.net.errs, secs)
	s.net = n

	d := readDisk()
	m.DiskRead, m.DiskWrite = perSecond(d.read, s.disk.read, secs), perSecond(d.written, s.disk.written, secs)
	s.disk = d

	mem := readMemInfo()
	m.MemTotal, m.MemUsed = mem.total, mem.total-mem.avail
	m.SwapTotal, m.SwapUsed = mem.swapTotal, mem.swapTotal-mem.swapFree

	var st syscall.Statfs_t
	if syscall.Statfs("/", &st) == nil {
		m.DiskTotal = st.Blocks * uint64(st.Bsize)
		m.DiskUsed = m.DiskTotal - st.Bavail*uint64(st.Bsize)
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 4 {
			m.Load1, _ = strconv.ParseFloat(f[0], 64)
			m.Load5, _ = strconv.ParseFloat(f[1], 64)
			m.Load15, _ = strconv.ParseFloat(f[2], 64)
			_, all, _ := strings.Cut(f[3], "/")
			m.Processes, _ = strconv.ParseUint(all, 10, 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
		m.Uptime = uint64(f)
	}

	m.TCPInUse, m.TCPTimeWait, m.UDPInUse = readSockstat()
	m.TCPEstablished = readEstablished()
	if b, err := os.ReadFile("/proc/sys/fs/file-nr"); err == nil {
		f := strings.Fields(string(b))
		if len(f) == 3 {
			alloc, _ := strconv.ParseUint(f[0], 10, 64)
			unused, _ := strconv.ParseUint(f[1], 10, 64)
			m.OpenFiles = alloc - min(alloc, unused)
			m.MaxOpenFiles, _ = strconv.ParseUint(f[2], 10, 64)
		}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.AgentGoroutines, m.AgentHeap = runtime.NumGoroutine(), ms.HeapAlloc
	m.AgentUptime = uint64(time.Since(agentStart).Seconds())
	return m
}

// readCPU returns idle and total jiffies.
func readCPU() (idle, total uint64) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(b), "\n")
	for i, f := range strings.Fields(line)[1:] {
		n, _ := strconv.ParseUint(f, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle and iowait
			idle += n
		}
	}
	return idle, total
}

// readNet sums counters over every non loopback interface.
func readNet() (n netCounters) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return n
	}
	for _, line := range strings.Split(string(b), "\n")[2:] {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 12 {
			continue
		}
		v := make([]uint64, 12)
		for i := range v {
			v[i], _ = strconv.ParseUint(f[i], 10, 64)
		}
		n.rx, n.rxPkts, n.errs = n.rx+v[0], n.rxPkts+v[1], n.errs+v[2]+v[3]+v[10]+v[11]
		n.tx, n.txPkts = n.tx+v[8], n.txPkts+v[9]
	}
	return n
}

// wholeDisk matches devices that are a disk rather than a partition, loop device or mapper.
var wholeDisk = regexp.MustCompile(`^(sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+)$`)

// readDisk sums bytes read and written over whole disks.
func readDisk() (d diskCounters) {
	b, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return d
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || !wholeDisk.MatchString(f[2]) {
			continue
		}
		r, _ := strconv.ParseUint(f[5], 10, 64)
		w, _ := strconv.ParseUint(f[9], 10, 64)
		d.read, d.written = d.read+r*512, d.written+w*512
	}
	return d
}

type memInfo struct{ total, avail, swapTotal, swapFree uint64 }

// readMemInfo reads memory and swap in bytes.
func readMemInfo() (m memInfo) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			m.total = n * 1024
		case "MemAvailable:":
			m.avail = n * 1024
		case "SwapTotal:":
			m.swapTotal = n * 1024
		case "SwapFree:":
			m.swapFree = n * 1024
		}
	}
	return m
}

// readSockstat reads TCP and UDP socket counts.
func readSockstat() (tcpInUse, tcpTimeWait, udpInUse uint64) {
	b, err := os.ReadFile("/proc/net/sockstat")
	if err != nil {
		return 0, 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		get := func(key string) uint64 {
			for i := 1; i+1 < len(f); i++ {
				if f[i] == key {
					n, _ := strconv.ParseUint(f[i+1], 10, 64)
					return n
				}
			}
			return 0
		}
		switch f[0] {
		case "TCP:":
			tcpInUse, tcpTimeWait = get("inuse"), get("tw")
		case "UDP:":
			udpInUse = get("inuse")
		}
	}
	return tcpInUse, tcpTimeWait, udpInUse
}

// readEstablished reads the number of established TCP connections.
func readEstablished() uint64 {
	b, err := os.ReadFile("/proc/net/snmp")
	if err != nil {
		return 0
	}
	lines := strings.Split(string(b), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "Tcp:") || !strings.HasPrefix(lines[i+1], "Tcp:") {
			continue
		}
		keys, vals := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		for j, k := range keys {
			if k == "CurrEstab" && j < len(vals) {
				n, _ := strconv.ParseUint(vals[j], 10, 64)
				return n
			}
		}
	}
	return 0
}

// readMemTotal is the installed memory in bytes.
func readMemTotal() uint64 {
	return readMemInfo().total
}

// readKernel is the kernel release.
func readKernel() string {
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}
