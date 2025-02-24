package dnsQueryUtil

import (
	"crypto"
	"errors"
	"os"
	"time"

	"github.com/miekg/dns"
)

const (
	TIMEDIFF int64 = 1000
)

var (
	errSigRRNil     = errors.New("error: Sig0.SigRR is nil")
	errPkNil        = errors.New("error: Sig0.Pk is nil")
	errSignerAssert = errors.New("error: It failed to assert crypto.Signer from Sig0.Pk")
)

type Sig0 struct {
	SigRR *dns.SIG
	Pk    crypto.PrivateKey
}

func NewSig0(sig0PublicPath string, sig0PrivatePath string) (s *Sig0, err error) {
	keyName, flags, sig0PublicKey, algorithm, err := SIG0PublicKeyExtract(sig0PublicPath)
	if err != nil {
		return nil, err
	}

	keyrr := new(dns.KEY)
	keyrr.Hdr.Name = keyName
	keyrr.Hdr.Rrtype = dns.TypeKEY
	keyrr.Hdr.Class = dns.ClassINET
	keyrr.Flags = flags
	keyrr.Protocol = 3 // fixed
	keyrr.Algorithm = algorithm
	keyrr.PublicKey = sig0PublicKey

	file, err := os.Open(sig0PrivatePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pk, err := keyrr.ReadPrivateKey(file, errReportFile)
	if err != nil {
		return nil, err
	}

	sigrr := new(dns.SIG)
	sigrr.Hdr.Name = "."
	sigrr.Hdr.Rrtype = dns.TypeSIG
	sigrr.Hdr.Class = dns.ClassANY
	sigrr.Algorithm = algorithm
	sigrr.SignerName = keyrr.Hdr.Name
	sigrr.KeyTag = keyrr.KeyTag()

	// ----------
	s = new(Sig0)
	s.SigRR = sigrr
	s.Pk = pk

	return s, nil
}

func (s *Sig0) SetMsgAuth(message *dns.Msg) (err error) {
	if s.SigRR == nil {
		return errSigRRNil
	}
	if s.Pk == nil {
		return errPkNil
	}

	sigrr := *s.SigRR
	nowTime := time.Now().Unix()
	sigrr.Inception = uint32(nowTime - TIMEDIFF)
	sigrr.Expiration = uint32(nowTime + TIMEDIFF)

	signer, ok := s.Pk.(crypto.Signer)
	if !ok {
		return errSignerAssert
	}

	m_pack, err := (&sigrr).Sign(signer, message)
	if err != nil {
		return err
	}

	// Maybe broken (If do so, try to divide to another *dns.Msg "m_unpack")
	if err = message.Unpack(m_pack); err != nil {
		return err
	}

	return nil
}
