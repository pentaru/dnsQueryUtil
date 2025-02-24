package dnsQueryUtil

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

const (
	SizeEDNS0 uint16 = 1232 // Recommended value for EDNS0
)

var (
	errCookieEmpty   = errors.New("error: cookie is empty")
	errExtraRRsExist = errors.New("error: extra RRs exist (edns must be set first)")
)

/*
CookieEDNS0 generates an 8-byte random cookie value for EDNS0.
*/
func NewCookieEDNS0() (cookie string, err error) {
	cookieByte := make([]byte, 8)
	_, err = rand.Read(cookieByte)
	if err != nil {
		return "", err
	}
	cookie = fmt.Sprintf("%x", cookieByte)

	return cookie, nil
}

/*
Set EDNS0 to the *message.

	Note: EDNS0 must be set first for messages.
	Note: this function does not check the duplication of EDNS0.
*/
func SetEdns0(message *dns.Msg, cookieValue string) (err error) {
	if message == nil {
		return errMessageNil
	}

	if cookieValue == "" {
		return errCookieEmpty
	}

	if len(message.Extra) > 0 {
		return errExtraRRsExist
	}

	// ------
	edns := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	edns.SetUDPSize(SizeEDNS0)

	// ------
	ednsCookie := &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: cookieValue,
	}
	edns.Option = append(edns.Option, ednsCookie)

	// ------
	message.Extra = append(message.Extra, edns)
	return nil
}
