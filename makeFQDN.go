package dnsQueryUtil

import (
	"errors"
	"strings"
)

var (
	errOriginEmpty    = errors.New("error: the origin domain is empty")
	errSubdomainEmpty = errors.New("error: the subdomain is empty")
)

/*
Construct a fully qualified domain name (FQDN) by combining a subdomain and an origin domain.
Both the subdomain and origin are ensured to have a trailing dot (".") if not already present.

	 Parameters:
		origin: The domain which has a SOA record (e.g., "home1.example.com")
		subdomain: The subdomain under the 'origin' domain (e.g., "IoTdevice1")

	 Returns:
		fqdn: The resulting fully qualified domain name (e.g., "IoTdevice1.home1.example.com.")
		err: An error if the origin or subdomain is empty
*/
func MakeFQDN(origin string, subdomain string) (fqdn string, err error) {
	if origin == "" {
		return "", errOriginEmpty
	}
	if subdomain == "" {
		return "", errSubdomainEmpty
	}

	if !strings.HasSuffix(origin, ".") {
		origin += "."
	}
	if !strings.HasSuffix(subdomain, ".") {
		subdomain += "."
	}

	fqdn = subdomain + origin
	return fqdn, nil
}
