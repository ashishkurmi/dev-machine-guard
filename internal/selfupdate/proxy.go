package selfupdate

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// machineProxy is the WinHTTP default (machine) proxy; nil means none. The
// SYSTEM updater has no user proxy env, so after the env vars this is what
// corporate proxy-only fleets rely on (spec Contracts: Proxy).
type machineProxy struct {
	servers map[string]string // scheme ("" = any) -> host:port
	bypass  []string
}

// NewHTTPClient returns the updater's client: the environment proxy vars
// first, then the WinHTTP machine proxy.
func NewHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = proxyFunc(http.ProxyFromEnvironment, loadMachineProxy())
	tr.TLSHandshakeTimeout = 30 * time.Second
	tr.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{Transport: tr}
}

func proxyFunc(env func(*http.Request) (*url.URL, error), mp *machineProxy) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if u, err := env(req); u != nil || err != nil {
			return u, err
		}
		if mp == nil {
			return nil, nil
		}
		return mp.proxyFor(req.URL), nil
	}
}

// parseWinHTTPProxy parses WINHTTP_PROXY_INFO strings: lpszProxy is a list
// of "[scheme=][scheme://]host[:port]" entries separated by ';' or spaces,
// lpszProxyBypass a list of host patterns ("<local>", "*.corp", "10.*").
func parseWinHTTPProxy(proxy, bypass string) *machineProxy {
	mp := &machineProxy{servers: map[string]string{}}
	for _, e := range splitList(proxy) {
		scheme := ""
		if i := strings.IndexByte(e, '='); i >= 0 {
			scheme, e = strings.ToLower(e[:i]), e[i+1:]
		}
		if i := strings.Index(e, "://"); i >= 0 {
			e = e[i+3:]
		}
		e = strings.TrimRight(e, "/")
		if e == "" {
			continue
		}
		if _, ok := mp.servers[scheme]; !ok {
			mp.servers[scheme] = e
		}
	}
	if len(mp.servers) == 0 {
		return nil
	}
	mp.bypass = splitList(bypass)
	return mp
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ' ' || r == '\t' || r == ',' })
}

func (mp *machineProxy) proxyFor(u *url.URL) *url.URL {
	host := strings.ToLower(u.Hostname())
	for _, b := range mp.bypass {
		if bypassMatch(strings.ToLower(b), host) {
			return nil
		}
	}
	server, ok := mp.servers[u.Scheme]
	if !ok {
		if server, ok = mp.servers[""]; !ok {
			if server, ok = mp.servers["http"]; !ok {
				return nil
			}
		}
	}
	return &url.URL{Scheme: "http", Host: server}
}

func bypassMatch(pattern, host string) bool {
	if pattern == "<local>" {
		return !strings.Contains(host, ".") || host == "localhost" || net.ParseIP(host).IsLoopback()
	}
	if i := strings.Index(pattern, "://"); i >= 0 {
		pattern = pattern[i+3:]
	}
	if h, _, err := net.SplitHostPort(pattern); err == nil {
		pattern = h
	}
	return wildcardMatch(pattern, host)
}

// wildcardMatch matches '*' against any run of characters.
func wildcardMatch(pattern, s string) bool {
	for len(pattern) > 0 {
		if pattern[0] == '*' {
			pattern = strings.TrimLeft(pattern, "*")
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if wildcardMatch(pattern, s[i:]) {
					return true
				}
			}
			return false
		}
		if s == "" || pattern[0] != s[0] {
			return false
		}
		pattern, s = pattern[1:], s[1:]
	}
	return s == ""
}
