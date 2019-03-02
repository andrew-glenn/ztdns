// Copyright © 2017 uxbh
// This file is part of github.com/uxbh/ztdns.

// Package dnssrv implements a simple DNS server.
package dnssrv

import (
	"fmt"
	"net"
	"time"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/miekg/dns"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
)

// Records contains the types of records the server will respond to.
type Records struct {
	A    []net.IP
	AAAA []net.IP
	CNAME []string
	PTR string
}

var dns_type_map = map[uint16]string{
	0: "None",
	1: "A",
	2: "NS",
	3: "MD",
	4: "MF",
	5: "CNAME",
	6: "SOA",
	7: "MB",
	8: "MG",
	9: "MR",
	10: "NULL",
	12: "PTR",
	13: "HINFO",
	14: "MINFO",
	15: "MX",
	16: "TXT",
	17: "RP",
	18: "AFSDB",
	19: "X25",
	20: "ISDN",
	21: "RT",
	23: "NSAPPTR",
	24: "SIG",
	25: "KEY",
	26: "PX",
	27: "GPOS",
	28: "AAAA",
	29: "LOC",
	30: "NXT",
	31: "EID",
	32: "NIMLOC",
	33: "SRV",
	34: "ATMA",
	35: "NAPTR",
	36: "KK",
	37: "CERT",
	39: "DNAME",
	41: "OPT",
	43: "DS",
	44: "SSHFP",
	46: "RRSIG",
	47: "NSEC",
	48: "DNSKEY",
	49: "DHCID",
	50: "NSEC3",
	51: "NSEC3PARAM",
	52: "TSLA",
	53: "SMIEA",
	55: "HIP",
	56: "NINFO",
	57: "RKEY",
	58: "TALINK",
	59: "CDS",
	60: "CDNSKEY",
	61: "OPENPGPKEY",
	62: "CSYNC",
	99: "SPF",
	100: "UINFO",
	101: "UID",
	102: "GID",
	103: "UNSPEC",
	104: "NID",
	105: "L32",
	106: "L64",
	107: "LP",
	108: "EUI48",
	109: "EUI64",
	256: "URI",
	257: "CAA",
	258: "AVC",
	249: "TKEY",
	250: "TSIG",
	251: "IXFR",
	252: "AXFR",
	253: "MAILB",
	254: "MAILA",
	255: "ANY",
	32768: "TA",
	32769: "DLV",
	65535: "Reserved",
}
// DNSUpdate is the last time the DNSDatabase was updated.
var DNSUpdate = time.Time{}

// DNSDatabase is a map of hostnames to the records associated with it.
var DNSDatabase = map[string]Records{}

var queryChan chan string

func soa(r *dns.Msg) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(r.Question[0].Name),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			// Has to be consistent with MinTTL to avoid invalidation
			Ttl: 1800,
		},
		Ns:      "ns.bullsh.it",
		Serial:  uint32(time.Now().Unix()),
		Mbox:    "hostmaster.bullsh.it",
		Refresh: 300,
		Retry:   300,
		Expire:  300,
		Minttl:  5,
	}
}

// addSOA is used to add an SOA record to a message for the given domain
func addSOA(msg *dns.Msg) {
	msg.Ns = append(msg.Ns, soa(msg))
}

// Start brings up a DNS server for the specified suffix on a given port.
func Start(iface string, port int, suffix string, req chan string) error {
	queryChan = req

	if port == 0 {
		port = 53
	}

	// attach request handler func
	dns.HandleFunc(".", handleDNSRequest)

	for _, addr := range getIfaceAddrs(iface) {
		for _, netname := range []string{"tcp", "udp"}{
			go func(suffix string, addr net.IP, port int, netname string) {
				var server *dns.Server
				if addr.To4().String() == addr.String() {
					log.Debugf("Creating IPv4 Server: %s:%d %s", addr, port, netname)
					server = &dns.Server{
						Addr: fmt.Sprintf("%s:%d", addr, port),
						Net:  netname,
					}
				} else {
					log.Debugf("Creating IPv6 Server: [%s]:%d %s6", addr, port, netname)
					server = &dns.Server{
						Addr: fmt.Sprintf("[%s]:%d", addr, port),
						Net:  fmt.Sprintf("%s6", netname),
					}
				}
				log.Printf("Starting server for %s on %s", suffix, server.Addr)
				err := server.ListenAndServe()
				if err != nil {
					log.Fatalf("failed to start DNS server: %s", err.Error())
				}
				defer server.Shutdown()
			}(suffix, addr, port, netname)
	}
}
	return nil
}

func getIfaceAddrs(iface string) []net.IP {
	if iface != "" {
		retaddrs := []net.IP{}
		netint, err := net.InterfaceByName(iface)
		if err != nil {
			log.Fatalf("Could not get interface: %s\n", err.Error())
		}
		addrs, err := netint.Addrs()
		if err != nil {
			log.Fatalf("Could not get addresses: %s\n", err.Error())
		}
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if !ip.IsLinkLocalUnicast() {
				log.Debugf("Found address: %s", ip.String())
				retaddrs = append(retaddrs, ip)
			}
		}
		return retaddrs
	}
	return []net.IP{net.IPv4zero}
}

// handleDNSRequest routes an incoming DNS request to a parser.
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		q := r.Question[0]
		log.Infof("Query: %s / %s", q.Name, dns_type_map[q.Qtype])
		switch q.Qtype{
		case dns.TypePTR:
			handlePTR(m)
		default:
			parseQuery(m)
		}
	}
  if len(m.Answer) == 0 {
		m.SetRcode(m, dns.RcodeNameError)
	}
	w.WriteMsg(m)
}

func handlePTR(m *dns.Msg) {
	q := m.Question[0]
	queryChan <- q.Name

	// Only add the SOA if requested
	if q.Qtype == dns.TypeSOA {
		addSOA(m)
	}

	// Get the QName without the domain suffix
	qName := strings.ToLower(dns.Fqdn(q.Name))
	queried_ip := dnsutil.ExtractAddressFromReverse(qName)
	if rec, ok := DNSDatabase[queried_ip]; ok  {
			rr, err := dns.NewRR(fmt.Sprintf("%s PTR %s", q.Name, rec.PTR))
			if err == nil{
				m.Answer = append(m.Answer, rr)
			}
	}
}

// parseQuery reads and creates an answer to a DNS query.
func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		q.Name = strings.ToLower(q.Name)
		queryChan <- q.Name
		if rec, ok := DNSDatabase[q.Name]; ok {
			switch q.Qtype {
			case dns.TypeA:
				for _, ip := range rec.A {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip.String()))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			case dns.TypeAAAA:
				for _, ip := range rec.AAAA {
					rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip.String()))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			case dns.TypeCNAME:
				for _, cname := range rec.CNAME {
					rr, err := dns.NewRR(fmt.Sprintf("%s CNAME %s", q.Name, cname))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		}
	}
}
