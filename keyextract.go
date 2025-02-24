package dnsQueryUtil

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

/*
Extract the key name, the algorithm name and the secret key from a TSIG key file.

TSIG common key template:

	key "<KEYNAME>" {
			algorithm <ALGONAME>;
			secret "<SECRET>";
	};
*/
func TSIGKeyExtract(filepath string) (keyName string, algorithm string, secret string, err error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		params := strings.Fields(line)

		switch params[0] {
		case "key":
			keyName = params[1][1:len(params[1])-1] + "."
		case "algorithm":
			algorithm = params[1][:len(params[1])-1] + "."
		case "secret":
			secret = params[1][1 : len(params[1])-2]
		}
	}

	if err = scanner.Err(); err != nil {
		return "", "", "", err
	}

	return keyName, algorithm, secret, nil
}

/*
Extract the keyname, the flag number, the public key and the algorithm number from the SIG(0) public key file.

SIG(0) public key template:

	<DOMAIN> IN KEY 0 3 10 <PUBLICKEY>
*/
func SIG0PublicKeyExtract(filepath string) (keyName string, flags uint16, publicKey string, algorithm uint8, err error) {
	sig0_public, err := os.ReadFile(filepath)
	if err != nil {
		return "", 0, "", 0, err
	}

	parameters := strings.Fields(string(sig0_public))

	keyName = parameters[0]
	flags64, err := strconv.ParseUint(parameters[3], 10, 16)
	if err != nil {
		return "", 0, "", 0, err
	}

	publicKey = strings.Join(parameters[6:], "")
	algorithm64, err := strconv.ParseUint(parameters[5], 10, 8)
	if err != nil {
		return "", 0, "", 0, err
	}

	return keyName, uint16(flags64), publicKey, uint8(algorithm64), nil
}
