//go:build linux

package collector

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// knownSafePorts: outbound connections to these are not flagged.
var knownSafePorts = map[int]bool{
	80: true, 443: true, 53: true, 22: true,
	8545: true, 8546: true, // Ethereum RPC
	9650:  true, // Avalanche
	26657: true, // Cosmos
}

// suspiciousPorts: always flag these.
var suspiciousPorts = map[int]bool{
	4444: true, 4445: true, 1337: true, 31337: true, // common reverse shell ports
	6666: true, 6667: true, 6668: true, // IRC C2
	9001: true, 9030: true, // Tor
}

type connKey struct {
	localIP    string
	localPort  int
	remoteIP   string
	remotePort int
}

// NetworkWatcher polls /proc/net/tcp(6) for new outbound connections.
type NetworkWatcher struct {
	interval time.Duration
	suppress *SuppressMatcher
	ioc      *IOCStore
	out      chan<- Event
	seen     map[connKey]struct{}
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// SetIOCStore attaches an indicator-of-compromise store consulted on every new
// outbound connection (matched before port heuristics so C2-over-443 is caught).
//
// MUST be called before Start. The field is read from the watcher goroutine
// without synchronisation, so calling it on a running watcher — e.g. from a
// future config-reload path — is a data race. Rebuild the watcher instead.
func (nw *NetworkWatcher) SetIOCStore(s *IOCStore) { nw.ioc = s }

func NewNetworkWatcher(interval time.Duration, out chan<- Event, suppress ...*SuppressMatcher) *NetworkWatcher {
	var sm *SuppressMatcher
	if len(suppress) > 0 {
		sm = suppress[0]
	}
	return &NetworkWatcher{
		interval: interval,
		suppress: sm,
		out:      out,
		seen:     make(map[connKey]struct{}),
		stop:     make(chan struct{}),
	}
}

func (nw *NetworkWatcher) Start() {
	nw.wg.Add(1)
	go nw.loop()
}

func (nw *NetworkWatcher) Stop() {
	nw.stopOnce.Do(func() { close(nw.stop) })
	nw.wg.Wait()
}

func (nw *NetworkWatcher) loop() {
	defer nw.wg.Done()
	ticker := time.NewTicker(nw.interval)
	defer ticker.Stop()

	// Baseline — don't alert on existing connections
	nw.scan(false)

	for {
		select {
		case <-nw.stop:
			return
		case <-ticker.C:
			nw.scan(true)
		}
	}
}

func (nw *NetworkWatcher) scan(emit bool) {
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		conns, err := parseProcNetTCP(procFile)
		if err != nil {
			continue
		}
		for _, c := range conns {
			if _, seen := nw.seen[c]; !seen {
				nw.seen[c] = struct{}{}
				if emit {
					nw.checkConnection(c)
				} else {
					// Baseline suppression applies to the noisy port
					// heuristics only. A known-bad indicator still alerts:
					// a resident C2 session predates the daemon on exactly
					// the hosts that matter (install-on-suspect-host, and
					// every Restart=always restart), and must not be
					// silently absorbed into the baseline.
					nw.checkIOC(c)
				}
			}
		}
	}
}

// checkIOC emits an alert if the remote IP matches a known-bad indicator.
// Reports whether a match was found, so the caller can skip the port
// heuristics. Safe to call on the baseline scan.
func (nw *NetworkWatcher) checkIOC(c connKey) bool {
	if c.remotePort == 0 {
		return false
	}
	m, ok := nw.ioc.MatchIP(c.remoteIP)
	if !ok {
		return false
	}
	e := NewIOCEvent(c.remoteIP, c.remotePort, m)
	if !nw.suppress.IsSuppressed(e) {
		// Cancellable: main closes the event bus after Stop; a send already in
		// flight would otherwise panic on the closed channel.
		select {
		case nw.out <- e:
		case <-nw.stop:
		}
	}
	return true
}

func (nw *NetworkWatcher) checkConnection(c connKey) {
	// Only care about ESTABLISHED outbound (remote port != 0)
	if c.remotePort == 0 || c.remoteIP == "0.0.0.0" || c.remoteIP == "::" {
		return
	}
	// Skip loopback
	if strings.HasPrefix(c.remoteIP, "127.") || c.remoteIP == "::1" {
		return
	}

	// IOC match takes precedence — a known-bad IP is flagged regardless of port,
	// catching C2/exfil over 443 that port heuristics treat as "safe".
	if nw.checkIOC(c) {
		return
	}

	sev := SeverityInfo
	detail := ""

	if suspiciousPorts[c.remotePort] {
		sev = SeverityCritical
		detail = fmt.Sprintf("port %d is a known reverse-shell/C2 port", c.remotePort)
	} else if !knownSafePorts[c.remotePort] {
		sev = SeverityMedium
		detail = fmt.Sprintf("connection to non-standard port %d", c.remotePort)
	} else {
		return // safe port, skip
	}

	e := Event{
		Source:    SourceNetwork,
		Timestamp: time.Now(),
		Action:    "connect",
		Resource:  fmt.Sprintf("%s:%d", c.remoteIP, c.remotePort),
		Detail:    detail,
		Severity:  sev,
	}
	if !nw.suppress.IsSuppressed(e) {
		// Cancellable: main closes the event bus after Stop; a send already in
		// flight would otherwise panic on the closed channel.
		select {
		case nw.out <- e:
		case <-nw.stop:
		}
	}
}

// parseProcNetTCP parses /proc/net/tcp or /proc/net/tcp6.
// Format: sl local_address rem_address st ...
func parseProcNetTCP(path string) ([]connKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var conns []connKey
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// state: 01 = ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		local, err := parseHexAddr(fields[1])
		if err != nil {
			continue
		}
		remote, err := parseHexAddr(fields[2])
		if err != nil {
			continue
		}
		conns = append(conns, connKey{
			localIP: local.IP.String(), localPort: local.Port,
			remoteIP: remote.IP.String(), remotePort: remote.Port,
		})
	}
	return conns, scanner.Err()
}

// parseHexAddr parses kernel hex address format "0100007F:0050" → 127.0.0.1:80
func parseHexAddr(s string) (*net.TCPAddr, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid addr: %s", s)
	}

	addrHex := parts[0]
	portHex := parts[1]

	portVal, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return nil, err
	}

	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil {
		return nil, err
	}

	// Kernel stores IPv4 in little-endian
	var ip net.IP
	if len(addrBytes) == 4 {
		ip = net.IP{addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0]}
	} else if len(addrBytes) == 16 {
		// IPv6: 4-byte groups, each little-endian
		rev := make([]byte, 16)
		for i := 0; i < 4; i++ {
			rev[i*4+0] = addrBytes[i*4+3]
			rev[i*4+1] = addrBytes[i*4+2]
			rev[i*4+2] = addrBytes[i*4+1]
			rev[i*4+3] = addrBytes[i*4+0]
		}
		ip = net.IP(rev)
	} else {
		return nil, fmt.Errorf("unexpected addr length: %d", len(addrBytes))
	}

	return &net.TCPAddr{IP: ip, Port: int(portVal)}, nil
}

// LogWatcher tails a log file for lines matching suspicious patterns.
func NewLogWatcher(logPath string, patterns []string, out chan<- Event) {
	slog.Info("log watcher not yet implemented", "path", logPath)
}
