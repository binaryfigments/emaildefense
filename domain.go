package emaildefense

import (
	"errors"
	"net"
	"strconv"

	"github.com/miekg/dns"
)

func checkAuthenticatedData(hostname string, nameserver string) (bool, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return false, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("domain lookup not successfull, code: " + strconv.Itoa(r.Rcode))
		return false, err
	}

	return r.AuthenticatedData, nil
}
