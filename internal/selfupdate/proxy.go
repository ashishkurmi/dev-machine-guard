package selfupdate

import (
	"net"
	"net/http"
	"net/url"
	"os"
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
	tr.Proxy = proxyFunc(envProxyFromOS(), loadMachineProxy())
	tr.TLSHandshakeTimeout = 30 * time.Second
	tr.ResponseHeaderTimeout = 60 * time.Second
	// Events share this client; no request follows https -> http.
	return &http.Client{Transport: tr, CheckRedirect: refuseDowngrade(nil)}
}

// envProxy is the environment's proxy configuration.
type envProxy struct {
	configured bool // HTTP(S)_PROXY set: its decision is final
	noProxy    string
	fn         func(*http.Request) (*url.URL, error)
}

func envProxyFromOS() envProxy {
	get := func(names ...string) string {
		for _, n := range names {
			if v := strings.TrimSpace(os.Getenv(n)); v != "" {
				return v
			}
		}
		return ""
	}
	return envProxy{
		configured: get("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy") != "",
		noProxy:    get("NO_PROXY", "no_proxy"),
		fn:         http.ProxyFromEnvironment,
	}
}

// proxyFunc: an env proxy config decides alone (NO_PROXY included); with
// none, NO_PROXY still sends listed hosts direct, then the WinHTTP machine
// proxy applies with its own bypass list.
func proxyFunc(env envProxy, mp *machineProxy) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if env.configured {
			return env.fn(req)
		}
		if mp == nil || noProxyMatch(env.noProxy, req.URL.Hostname()) {
			return nil, nil
		}
		return mp.proxyFor(req.URL), nil
	}
}

// noProxyMatch applies NO_PROXY: "*", host names (matching the host and
// its subdomains, with or without a leading dot), IPs and CIDRs; ports are
// ignored.
func noProxyMatch(list, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := net.ParseIP(host)
	for _, e := range strings.Split(list, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if e == "*" {
			return true
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			if ip != nil && n.Contains(ip) {
				return true
			}
			continue
		}
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		if eip := net.ParseIP(e); eip != nil {
			if ip != nil && eip.Equal(ip) {
				return true
			}
			continue
		}
		e = strings.TrimPrefix(strings.TrimPrefix(e, "*"), ".")
		if host == e || strings.HasSuffix(host, "."+e) {
			return true
		}
	}
	return false
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
