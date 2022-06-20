package ssh

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
)

func publicKeyAuthentication() func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	var keyIsOk = checkPubKeyIsInFile("AUTHORIZED_KEYS_FILE")

	return func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		if keyIsOk(pubKey) {
			return &ssh.Permissions{
				// Record the public key used for authentication.
				Extensions: map[string]string{
					"pubkey-fp":  ssh.FingerprintSHA256(pubKey),
					"pubkey-ish": fingerprintIsh(pubKey),
					"pubkey":     string(ssh.MarshalAuthorizedKey(pubKey)),
				},
			}, nil
		} else {
			return nil, fmt.Errorf("key not authorized")
		}

	}
}

func checkPubKeyIsInFile(environmentVariableName string) func(ssh.PublicKey) bool {
	var yes = func(ssh.PublicKey) bool {
		return true
	}
	if os.Getenv(environmentVariableName) == "" {
		return yes
	}
	readFile, err := os.Open(os.Getenv(environmentVariableName))
	if err != nil {
		return yes
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var keys = make(map[string]bool)
	for fileScanner.Scan() {
		var pubKey, _, _, _, err = ssh.ParseAuthorizedKey(fileScanner.Bytes())
		if err == nil {
			keys[string(ssh.MarshalAuthorizedKey(pubKey))] = true
		}
	}
	_ = readFile.Close()
	return func(pubKey ssh.PublicKey) bool {
		var marshalled = string(ssh.MarshalAuthorizedKey(pubKey))
		var _, found = keys[marshalled]
		return found
	}
}
