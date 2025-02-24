package dnsQueryUtil

import (
	"crypto/x509"
	"errors"
)

/*
VerifyPeer verifies a certificate to check its validity with x509.

Note: This function does not check chains of trust.
*/
func VerifyPeer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if rawCerts == nil {
		return errors.New("certificates are null")
	}
	if len(rawCerts) == 0 {
		return errors.New("certificates are empty")
	}

	// read a certificate
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return errors.New("failed to parse certificate")
	}

	// create a pool and an option for verifying
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	opts := x509.VerifyOptions{Roots: certPool}

	// do verification
	_, err = cert.Verify(opts)
	if err != nil {
		return err
	}

	return nil
}
