package dnsQueryUtil

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	UDP           string = "udp"
	TCP           string = "tcp"
	TLS           string = "tcp-tls"
	AuthNone      int    = 0
	AuthTsig      int    = 1
	AuthSig0      int    = 2
	errReportFile string = "./test.txt"
)

var (
	wg             sync.WaitGroup
	ProtocolToPort = map[string]int{
		"":  53, // Default -> UDP
		UDP: 53,
		TCP: 53,
		TLS: 853,
	}
)

var (
	errClientNil          = errors.New("error: q.Client is nil")
	errMessageNil         = errors.New("error: message is nil")
	errMessageFieldNil    = errors.New("error: q.Message is nil")
	errMethodFieldNil     = errors.New("error: q.Tsig or q.Sig0 is nil")
	errProtocolInvalid    = errors.New("error: protocol is invalid")
	errAuthMethodInvalid  = errors.New("error: authMethod is invalid")
	errAuthKeyFileInvalid = errors.New("error: key files for authentication are not specified or invalid")
	errAnswerTruncated    = errors.New("error: the answer was truncated by the DNS server")
	errQtypeNameUnknown   = errors.New("error: the qtype name is unknown")
)

type SetMsgAuther interface {
	SetMsgAuth(*dns.Msg) error
}

type Query struct {
	Client  *dns.Client
	Cookie  string // Used for EDNS0 (If empty -> EDNS0 is not used)
	Message *dns.Msg
	Tsig    *Tsig // for TSIG
	Sig0    *Sig0 // for SIG(0)
}

/*
closeConn closes the connection of conn gracefully.
*/
func closeConn(protocol string, conn net.Conn) {
	if protocol != TLS {
		conn.Close()
		return
	}

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		log.Println("error: the assertion to *tls.Conn failed")
		conn.Close()
		return
	}

	defer tlsConn.Close()
	if err := tlsConn.CloseWrite(); err != nil {
		log.Println(err.Error())
		return
	}

	reader := bufio.NewScanner(tlsConn)
	reader.Scan()
}

/*
NewQuery returns *Query with Client, Protocol, Cookie *if needed*, Authentication (TSIG or SIG(0)) *if needed*.

	protocol -> "" or UDP ("udp"): UDP, TCP ("tcp"): TCP, TLS ("tcp-tls"): TLS
	useEdns  -> true: Set q.Cookie, false: Do not set q.Cookie
	timeout  -> int (unit: second)
	authMethod -> authNone (0) | authTsig (1) | authSig0 (2)
	authKey  -> None: nil/empty, TSIG: a TSIG key, SIG(0): a public SIG(0) key and a private one
*/
func NewQuery(protocol string, useEdns bool, timeout int, authMethod int, authKey []string) (q *Query, err error) {
	q = new(Query)

	if err := q.SetClient(timeout, protocol); err != nil {
		return nil, err
	}

	if useEdns {
		if err := q.SetCookie(); err != nil {
			return nil, err
		}
	}

	switch authMethod {
	case AuthNone:
		// Do nothing
	case AuthTsig:
		if len(authKey) != 1 {
			return nil, errAuthKeyFileInvalid
		}
		if err := q.SetTsig(authKey[0]); err != nil {
			return nil, err
		}
	case AuthSig0:
		if len(authKey) != 2 {
			return nil, errAuthKeyFileInvalid
		}
		if err := q.SetSig0(authKey[0], authKey[1]); err != nil {
			return nil, err
		}
	default:
		return nil, errAuthMethodInvalid
	}

	return q, nil
}

/*
SendQuery sends a query message to a server.

This function should not be called directly. Instead, you should call wrapper functions.

	Note: "message" must be specified.
	Note: EDNS0 is not set in this function.
*/
func (q *Query) SendQuery(server string, message *dns.Msg) (answer *dns.Msg, err error) {
	if q.Client == nil {
		return nil, errClientNil
	}
	if message == nil {
		return nil, errMessageNil
	}

	// ------
	portNum, ok := ProtocolToPort[q.Client.Net]
	if !ok {
		return nil, errProtocolInvalid
	}

	conn, err := q.Client.Dial(fmt.Sprintf("%s:%d", server, portNum))
	if err != nil {
		return nil, err
	}

	answer, _, err = q.Client.ExchangeWithConn(message, conn)
	defer closeConn(q.Client.Net, conn.Conn)
	if err != nil {
		return nil, err
	}

	if answer.MsgHdr.Rcode != 0 {
		return nil, errors.New(answer.String())
	}
	if answer.MsgHdr.Truncated {
		return nil, errAnswerTruncated
	}

	return answer, nil
}

func (q *Query) SendUpdateQueryWrapper(serverList []string, doRetry bool) (err error) {
	serverNum := len(serverList)
	errChannel := make(chan error, serverNum)

	// Send the Message to each server with a parallel
	for _, server := range serverList {
		wg.Add(1)

		go func(server string) {
			defer func() {
				if r := recover(); r != nil {
					log.Println("Recovered:", r)
					errChannel <- errors.New("sendQueryWrapper: recover")
				}
				wg.Done()
			}()

			_, err := q.SendQueryWrapper(server, doRetry)
			if err != nil {
				errChannel <- err
			}
		}(server)
	}

	wg.Wait()
	if len(errChannel) > 0 {
		return <-errChannel
	}

	return nil
}

/*
SendQueryWrapper sends a query message to a server.

Generally, it is recommended to use this wrapper when sending queries in this module.

	If q.Tsig is specified:  TSIG
	If q.SigRR is specified: SIG(0)
	Otherwise: No authentication

	doRetry: true -> Repeat sending queries until errors do not happen
*/
func (q *Query) SendQueryWrapper(server string, doRetry bool) (answer *dns.Msg, err error) {
	authMethod := q.CheckAuthMethod()
	for {
		switch authMethod {
		case AuthNone:
			answer, err = q.SendQueryHelper(q, server)
		case AuthTsig:
			answer, err = q.SendQueryHelper(q.Tsig, server)
		case AuthSig0:
			answer, err = q.SendQueryHelper(q.Sig0, server)
		}

		if doRetry && err != nil {
			log.Printf("Retry in %s: %s\n", server, err.Error())
			time.Sleep(time.Second)
			continue
		}
		break
	}

	return answer, err
}

/*
SendQueryHelper sends a query message to a server with TSIG or SIG(0) or nothing.

	setAuther -> *q: None, *Tsig: TSIG, *Sig0: SIG(0)
*/
func (q *Query) SendQueryHelper(setAuther SetMsgAuther, server string) (answer *dns.Msg, err error) {
	if q.Message == nil {
		return nil, errMessageFieldNil
	}
	if setAuther == nil {
		return nil, errMethodFieldNil
	}

	// ------
	message := *q.Message

	if q.IsEnableEdns() {
		if err := q.SetEdns(&message); err != nil {
			return nil, err
		}
	}

	if err := setAuther.SetMsgAuth(&message); err != nil {
		return nil, err
	}

	answer, err = q.SendQuery(server, &message)
	return answer, err
}

func (q *Query) SetCookie() (err error) {
	cookie, err := NewCookieEDNS0()
	if err != nil {
		return err
	}

	q.Cookie = cookie
	return nil
}

func (q *Query) SetEdns(message *dns.Msg) (err error) {
	if err := SetEdns0(message, q.Cookie); err != nil {
		return err
	}
	return nil
}

/*
This implementation does nothing.

(To send a UDP message in SendQueryWrapper)

	return: always nil
*/
func (q *Query) SetMsgAuth(message *dns.Msg) error {
	// Do nothing
	return nil
}

/*
SetClient sets q.Client, q.CLient.Timeout, q.Client.Net and q.Client.TLSConfig *If needed*.

	timeout: int (unit: ms)

Note: This function does not release the previous client.
*/
func (q *Query) SetClient(timeout int, protocol string) (err error) {
	if q.Client == nil {
		q.Client = new(dns.Client)
	}
	if _, ok := ProtocolToPort[protocol]; !ok {
		return errProtocolInvalid
	}

	if protocol == TLS {
		q.Client.TLSConfig = &tls.Config{
			ClientSessionCache:    tls.NewLRUClientSessionCache(0),
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: VerifyPeer,
		}
	}

	q.Client.Timeout = time.Duration(timeout) * time.Millisecond
	q.Client.Net = protocol

	return nil
}

func (q *Query) SetTsig(tsigPath string) (err error) {
	if q.Client == nil {
		return errClientNil
	}

	t, err := NewTsig(tsigPath)
	if err != nil {
		return err
	}
	q.Client.TsigSecret = map[string]string{t.TsigDomain: t.TsigKey} // need to add "." to key name
	q.Tsig = t

	return nil
}

/*
SetSig0 sets pk and SigRR fields from SIG(0) key files.
*/
func (q *Query) SetSig0(sig0PublicPath string, sig0PrivatePath string) (err error) {
	s, err := NewSig0(sig0PublicPath, sig0PrivatePath)
	if err != nil {
		return err
	}
	q.Sig0 = s

	return nil
}

/*
SendQuestionMessage sets an inquiry message to the *Query.Message.

Note: The previous message is removed when using this function.
*/
func (q *Query) SetQuestionMessage(domain string, qtype uint16, recursion bool) (err error) {
	q.Message = nil
	m := new(dns.Msg)

	m.Id = dns.Id()
	m.RecursionDesired = recursion
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Name: domain, Qtype: qtype, Qclass: dns.ClassINET}

	q.Message = m
	return nil
}

/*
SetUpdateMessage sets an update message to the *Query.Message.

	origin: The domain which has a SOA record
	subdomain: The subdomain name under the "origin" domain
	qtype: dns.TypeA | dns.TypeAAAA | dns.TypeNS | dns.TypeMX | dns.TypeTXT | etc...

Note: The previous message is removed when using this function.
*/
func (q *Query) SetUpdateMessage(origin string, subdomain string, ttl int, qtype uint16, data string) (err error) {
	fqdn, err := MakeFQDN(origin, subdomain)
	if err != nil {
		return err
	}

	q.Message = nil
	m := new(dns.Msg)
	m.SetUpdate(origin)

	qtypeName, ok := dns.TypeToString[qtype]
	if !ok {
		return errQtypeNameUnknown
	}

	delrr, _ := dns.NewRR(fmt.Sprintf("%s 0 IN %s", fqdn, qtypeName))
	insrr, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", fqdn, ttl, qtypeName, data))

	m.RemoveRRset([]dns.RR{delrr})
	m.Insert([]dns.RR{insrr})

	q.Message = m
	return nil
}

/*
IsUseEdns checks whether EDNS0 is enabled in *Query.

	Return:
	false 	(if q.Cookie == "")
	true	(otherwise)
*/
func (q *Query) IsEnableEdns() bool {
	if q.Cookie == "" {
		return false
	} else {
		return true
	}
}

/*
CheckAuthMethod checks what type of authentication is used in *Query.

	Return: authNone (0) | authTsig (1) | authSig0 (2)

Note: If both TSIG and SIG(0) exist, prioritize TSIG.
*/
func (q *Query) CheckAuthMethod() int {
	if q.Tsig != nil {
		return AuthTsig
	} else if q.Sig0 != nil {
		return AuthSig0
	} else {
		return AuthNone
	}
}
