package l7

import (
	"bufio"
	"encoding/binary"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
)

// Free, redistributable data sources. GeoIP/ASN come from the ip-location-db
// project; VPN and datacenter ranges from the X4BNet lists.
const (
	urlCountryDB   = "https://raw.githubusercontent.com/sapics/ip-location-db/main/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv"
	urlASNDB       = "https://raw.githubusercontent.com/sapics/ip-location-db/main/asn/asn-ipv4.csv"
	urlVPNList     = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"
	urlDatacenters = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"

	listRefreshInterval = 24 * time.Hour
)

// cidrSet is a static set of networks (used for the per-allocation IP
// whitelist/blacklist rules).
type cidrSet struct {
	nets []*net.IPNet
}

func newCidrSet(entries []string) *cidrSet {
	s := &cidrSet{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if strings.Contains(e, ":") {
				e += "/128"
			} else {
				e += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			s.nets = append(s.nets, n)
		}
	}
	return s
}

func (s *cidrSet) empty() bool { return s == nil || len(s.nets) == 0 }

func (s *cidrSet) contains(ip net.IP) bool {
	if s == nil {
		return false
	}
	for _, n := range s.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ipRange is one row of a range database, values are big-endian IPv4.
type ipRange struct {
	start, end uint32
	country    string
	asn        uint32
}

type rangeDB struct {
	rows []ipRange
}

func (db *rangeDB) lookup(v uint32) *ipRange {
	if db == nil || len(db.rows) == 0 {
		return nil
	}
	i := sort.Search(len(db.rows), func(i int) bool { return db.rows[i].end >= v })
	if i < len(db.rows) && db.rows[i].start <= v && v <= db.rows[i].end {
		return &db.rows[i]
	}
	return nil
}

func ipv4ToUint(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

// listService lazily downloads and refreshes the shared IP intelligence
// databases. Lookups fail open: while data is missing every check returns the
// zero value so players are never blocked because a download failed.
type listService struct {
	mu  sync.Mutex
	dir string

	needGeo, needASN, needVPN bool
	started                   map[string]bool

	geo *rangeDB
	asn *rangeDB
	vpn *cidrSet
}

func newListService(dir string) *listService {
	return &listService{dir: dir, started: make(map[string]bool)}
}

// require marks which databases are needed by at least one active proxy and
// spawns refresh loops for newly required ones.
func (l *listService) require(geo, asn, vpn bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.needGeo = l.needGeo || geo
	l.needASN = l.needASN || asn
	l.needVPN = l.needVPN || vpn
	if l.needGeo && !l.started["geo"] {
		l.started["geo"] = true
		go l.refreshLoop("geo")
	}
	if l.needASN && !l.started["asn"] {
		l.started["asn"] = true
		go l.refreshLoop("asn")
	}
	if l.needVPN && !l.started["vpn"] {
		l.started["vpn"] = true
		go l.refreshLoop("vpn")
	}
}

func (l *listService) refreshLoop(kind string) {
	for {
		if err := l.refresh(kind); err != nil {
			log.WithField("subsystem", "l7").WithField("list", kind).WithField("error", err).Warn("failed to refresh IP intelligence list")
			time.Sleep(15 * time.Minute)
			continue
		}
		time.Sleep(listRefreshInterval)
	}
}

func (l *listService) cachePath(name string) string {
	return filepath.Join(l.dir, name)
}

// fetch downloads url to a cache file unless the cached copy is still fresh,
// then returns the cache path.
func (l *listService) fetch(url, name string) (string, error) {
	if err := os.MkdirAll(l.dir, 0o755); err != nil {
		return "", err
	}
	p := l.cachePath(name)
	if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) < listRefreshInterval && st.Size() > 0 {
		return p, nil
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	res, err := client.Get(url)
	if err != nil {
		// Keep serving a stale cache copy if one exists.
		if _, serr := os.Stat(p); serr == nil {
			return p, nil
		}
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		if _, serr := os.Stat(p); serr == nil {
			return p, nil
		}
		return "", errMalformedFrame
	}
	tmp := p + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	w := bufio.NewWriter(f)
	if _, err := w.ReadFrom(res.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	f.Close()
	if err := os.Rename(tmp, p); err != nil {
		return "", err
	}
	return p, nil
}

func (l *listService) refresh(kind string) error {
	switch kind {
	case "geo":
		p, err := l.fetch(urlCountryDB, "country-ipv4.csv")
		if err != nil {
			return err
		}
		db, err := loadRangeCSV(p, func(fields []string, r *ipRange) bool {
			if len(fields) < 3 {
				return false
			}
			r.country = strings.ToUpper(strings.TrimSpace(fields[2]))
			return r.country != ""
		})
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.geo = db
		l.mu.Unlock()
		log.WithField("subsystem", "l7").WithField("ranges", len(db.rows)).Info("loaded GeoIP country database")
	case "asn":
		p, err := l.fetch(urlASNDB, "asn-ipv4.csv")
		if err != nil {
			return err
		}
		db, err := loadRangeCSV(p, func(fields []string, r *ipRange) bool {
			if len(fields) < 3 {
				return false
			}
			v, err := strconv.ParseUint(strings.TrimSpace(fields[2]), 10, 32)
			if err != nil {
				return false
			}
			r.asn = uint32(v)
			return true
		})
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.asn = db
		l.mu.Unlock()
		log.WithField("subsystem", "l7").WithField("ranges", len(db.rows)).Info("loaded ASN database")
	case "vpn":
		set := &cidrSet{}
		for i, src := range []struct{ url, name string }{
			{urlVPNList, "vpn-ipv4.txt"},
			{urlDatacenters, "datacenter-ipv4.txt"},
		} {
			p, err := l.fetch(src.url, src.name)
			if err != nil {
				if i == 0 {
					return err
				}
				continue
			}
			if err := loadCIDRFile(p, set); err != nil {
				return err
			}
		}
		l.mu.Lock()
		l.vpn = set
		l.mu.Unlock()
		log.WithField("subsystem", "l7").WithField("networks", len(set.nets)).Info("loaded VPN/datacenter ranges")
	}
	return nil
}

func loadRangeCSV(path string, parse func([]string, *ipRange) bool) (*rangeDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db := &rangeDB{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		start := net.ParseIP(strings.TrimSpace(fields[0]))
		end := net.ParseIP(strings.TrimSpace(fields[1]))
		if start == nil || end == nil {
			continue
		}
		s, ok1 := ipv4ToUint(start)
		e, ok2 := ipv4ToUint(end)
		if !ok1 || !ok2 || s > e {
			continue
		}
		r := ipRange{start: s, end: e}
		if !parse(fields, &r) {
			continue
		}
		db.rows = append(db.rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(db.rows, func(i, j int) bool { return db.rows[i].start < db.rows[j].start })
	return db, nil
}

func loadCIDRFile(path string, set *cidrSet) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		if _, n, err := net.ParseCIDR(line); err == nil {
			set.nets = append(set.nets, n)
		}
	}
	return sc.Err()
}

// countryOf returns the ISO country code for an address or "" while unknown.
func (l *listService) countryOf(ip net.IP) string {
	v, ok := ipv4ToUint(ip)
	if !ok {
		return ""
	}
	l.mu.Lock()
	db := l.geo
	l.mu.Unlock()
	if r := db.lookup(v); r != nil {
		return r.country
	}
	return ""
}

// asnOf returns the autonomous system number for an address or 0.
func (l *listService) asnOf(ip net.IP) uint32 {
	v, ok := ipv4ToUint(ip)
	if !ok {
		return 0
	}
	l.mu.Lock()
	db := l.asn
	l.mu.Unlock()
	if r := db.lookup(v); r != nil {
		return r.asn
	}
	return 0
}

// isVPN reports whether the address belongs to a known VPN/datacenter range.
func (l *listService) isVPN(ip net.IP) bool {
	l.mu.Lock()
	set := l.vpn
	l.mu.Unlock()
	return set.contains(ip)
}
