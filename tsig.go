package dnsQueryUtil

import (
	"errors"
	"time"

	"github.com/miekg/dns"
)

var (
	errDomainInvalid = errors.New("error: TsigDomain is invalid")
	errAlgoInvalid   = errors.New("error: TsigAlgorithm is invalid")
)

type Tsig struct {
	TsigDomain    string
	TsigAlgorithm string
	TsigKey       string
}

func NewTsig(tsigPath string) (t *Tsig, err error) {
	tsigDomain, algorithm, tsigKey, err := TSIGKeyExtract(tsigPath)
	if err != nil {
		return nil, err
	}

	t = new(Tsig)
	t.TsigDomain = tsigDomain
	t.TsigAlgorithm = algorithm
	t.TsigKey = tsigKey

	return t, nil
}

func (t *Tsig) SetMsgAuth(message *dns.Msg) (err error) {
	if t.TsigDomain == "" {
		return errDomainInvalid
	}
	if t.TsigAlgorithm == "" {
		return errAlgoInvalid
	}

	message.SetTsig(t.TsigDomain, t.TsigAlgorithm, 300, time.Now().Unix())
	return nil
}
