package gate

import (
	"crypto/sha256"
	"crypto/subtle"
	"sort"
	"sync"
	"sync/atomic"
)

// registry is the process wide state shared by the gate handlers and the admin api. It outlives config reloads, so
// users, counters and open tunnels carry over when the server config changes.
var registry = &state{
	users:    map[string]map[string][32]byte{},
	usage:    map[string]*counter{},
	sessions: map[*session]struct{}{},
}

type counter struct{ up, down atomic.Int64 }

type state struct {
	mu       sync.Mutex
	users    map[string]map[string][32]byte // inbound -> user name -> sha256 of the password
	usage    map[string]*counter            // user name -> bytes since the last drain
	sessions map[*session]struct{}
}

// session is one open tunnel.
type session struct {
	inbound, user, ip string
	kick              func()
}

// Credential is one account as the panel hands it over.
type Credential struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Usage is traffic of one user since the previous drain.
type Usage struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Report is what a drain returns.
type Report struct {
	Users  map[string]Usage    `json:"users"`
	Online map[string][]string `json:"online"`
}

// replace makes the users of an inbound exactly creds and cuts every tunnel of a user that is gone or whose password
// changed. It returns how many tunnels it cut.
func (s *state) replace(inbound string, creds []Credential) int {
	next := make(map[string][32]byte, len(creds))
	for _, c := range creds {
		next[c.Name] = sha256.Sum256([]byte(c.Password))
	}

	s.mu.Lock()
	old := s.users[inbound]
	s.users[inbound] = next
	var cut []*session
	for sess := range s.sessions {
		if sess.inbound != inbound {
			continue
		}
		if sum, ok := next[sess.user]; !ok || sum != old[sess.user] {
			cut = append(cut, sess)
		}
	}
	s.mu.Unlock()

	for _, sess := range cut {
		sess.kick()
	}
	return len(cut)
}

// check reports whether name and password are a current user of the inbound.
func (s *state) check(inbound, name, password string) bool {
	s.mu.Lock()
	want, ok := s.users[inbound][name]
	s.mu.Unlock()
	got := sha256.Sum256([]byte(password))
	// compare even for an unknown name, so timing does not tell which names exist
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1 && ok
}

// open registers a tunnel of a user. The returned function closes it.
func (s *state) open(sess *session) (c *counter, done func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.usage[sess.user] == nil {
		s.usage[sess.user] = &counter{}
	}
	s.sessions[sess] = struct{}{}
	return s.usage[sess.user], func() {
		s.mu.Lock()
		delete(s.sessions, sess)
		s.mu.Unlock()
	}
}

// drain returns and resets the counters and lists who is connected.
func (s *state) drain() Report {
	s.mu.Lock()
	defer s.mu.Unlock()

	rep := Report{Users: map[string]Usage{}, Online: map[string][]string{}}
	for name, c := range s.usage {
		up, down := c.up.Swap(0), c.down.Swap(0)
		if up != 0 || down != 0 {
			rep.Users[name] = Usage{Up: up, Down: down}
		}
	}
	live := map[string]bool{}
	for sess := range s.sessions {
		live[sess.user] = true
		ips := rep.Online[sess.user]
		if ips == nil {
			ips = []string{}
		}
		if sess.ip != "" && !contains(ips, sess.ip) {
			ips = append(ips, sess.ip)
		}
		rep.Online[sess.user] = ips
	}
	for name := range rep.Online {
		sort.Strings(rep.Online[name])
	}
	// a user that is gone and idle needs no counter any more
	known := map[string]bool{}
	for _, users := range s.users {
		for name := range users {
			known[name] = true
		}
	}
	for name := range s.usage {
		if !known[name] && !live[name] {
			delete(s.usage, name)
		}
	}
	return rep
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
