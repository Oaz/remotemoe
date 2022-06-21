package ssh

import (
	"bufio"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"os"
)

func publicKeyAuthentication(authorizedKeysFilePath string) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	readFile, err := os.Open(authorizedKeysFilePath)
	if err != nil {
		return permissionsWithoutAuthentication
	}
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	var trustedKeys = make(map[string]bool)
	for fileScanner.Scan() {
		var pubKey, _, _, _, err = ssh.ParseAuthorizedKey(fileScanner.Bytes())
		if err == nil {
			log.Printf("trust %s %s", pubKey.Type(), ssh.FingerprintSHA256(pubKey))
			trustedKeys[string(ssh.MarshalAuthorizedKey(pubKey))] = true
		}
	}
	_ = readFile.Close()

	return func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		var certificate, isCertificate = pubKey.(*ssh.Certificate)
		if isCertificate {
			return permissionsForCertificate(c, certificate, trustedKeys)
		} else {
			return permissionsForAuthorizedPublicKey(c, pubKey, trustedKeys)
		}
	}
}

func isTrusted(pubKey ssh.PublicKey, authorizedKeys map[string]bool) bool {
	var marshalled = string(ssh.MarshalAuthorizedKey(pubKey))
	var _, found = authorizedKeys[marshalled]
	return found
}

func permissionsWithoutAuthentication(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	return &ssh.Permissions{
		// Record the public key used for authentication.
		Extensions: map[string]string{
			"pubkey-fp":  ssh.FingerprintSHA256(pubKey),
			"pubkey-ish": fingerprintIsh(pubKey),
			"pubkey":     string(ssh.MarshalAuthorizedKey(pubKey)),
		},
	}, nil
}

func permissionsForAuthorizedPublicKey(c ssh.ConnMetadata, pubKey ssh.PublicKey, authorizedKeys map[string]bool) (*ssh.Permissions, error) {
	if isTrusted(pubKey, authorizedKeys) {
		return permissionsWithoutAuthentication(c, pubKey)
	} else {
		return nil, fmt.Errorf("key not authorized")
	}
}

func permissionsForCertificate(c ssh.ConnMetadata, certificate *ssh.Certificate, authorizedKeys map[string]bool) (*ssh.Permissions, error) {
	if !isTrusted(certificate.SignatureKey, authorizedKeys) {
		return nil, fmt.Errorf("certificate signed by unrecognized authority")
	}
	var certChecker = ssh.CertChecker{}
	var certificateError = certChecker.CheckCert(c.User(), certificate)
	if certificateError != nil {
		return nil, certificateError
	}
	var permissions, _ = permissionsWithoutAuthentication(c, certificate.Key)
	return &ssh.Permissions{
		CriticalOptions: merge(permissions.CriticalOptions, certificate.CriticalOptions),
		Extensions:      merge(permissions.Extensions, certificate.Extensions),
	}, nil
}

func merge(m1 map[string]string, m2 map[string]string) map[string]string {
	for k, v := range m2 {
		m1[k] = v
	}
	return m1
}
