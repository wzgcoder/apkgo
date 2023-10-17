package xiaomi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const key_size = 1024
const group_size = key_size / 8
const encrypt_group_size = group_size - 11

const publicCer = `-----BEGIN CERTIFICATE-----
MIICsjCCAhugAwIBAgIUbANcYrk1DOkSSBAxRZo+FcIru9wwDQYJKoZIhvcNAQEE
BQAwajELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaUppbmcxEDAOBgNVBAcMB0Jl
aUppbmcxDzANBgNVBAoMBnhpYW9taTENMAsGA1UECwwEbWl1aTEXMBUGA1UEAwwO
ZGV2LnhpYW9taS5jb20wIBcNMjMwMjIxMDIwOTA2WhgPMjEyMzAxMjgwMjA5MDZa
MGoxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlKaW5nMRAwDgYDVQQHDAdCZWlK
aW5nMQ8wDQYDVQQKDAZ4aWFvbWkxDTALBgNVBAsMBG1pdWkxFzAVBgNVBAMMDmRl
di54aWFvbWkuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAX+S8xIjM
tIvC3hDV1Pb9G0xeHKDP5C3yukb41kuvf+rVMTcSb4wxTWy7JlOMaRd6hWPUSNKs
kX+/aZin2FHlqJkAjP4SqNpSiG1le/0VYXmYRAtshm1DEcoCMyatwAoQU9jDtWu2
wPSyDXL/sS5qMufpdzJ1cG1VKVrAvxiOfQIDAQABo1MwUTAdBgNVHQ4EFgQUSerM
KItNhZ/Od9mhtMVd4vE/pBEwHwYDVR0jBBgwFoAUSerMKItNhZ/Od9mhtMVd4vE/
pBEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQQFAAOBgQCpyfyMQ1tXgiwb
d6j4kU8suUwwFdRcpnjoABwndExs38XF7EoLcHFHpt3WUmIs4fdnOD6+549n0usG
OCkRb8H47P7Y+qnJgH/YM42sZEp4vVHczr7MyOquQC/ZO5gnAwaYoVMkKqs06u5d
P/MMoedva3PCu9tBkNSQpAnle2BiYg==
-----END CERTIFICATE-----
`

func loadPublicKeyFromCert() (*rsa.PublicKey, error) {
	// certData, err := os.ReadFile(cerFilePath)
	// if err != nil {
	// 	return nil, err
	// }
	block, _ := pem.Decode([]byte(publicCer))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM data")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key type")
	}
	return publicKey, nil
}

func encryptByPublicKey(plaintext []byte, publicKey *rsa.PublicKey) (string, error) {
	encryptedData := make([]byte, 0)
	for len(plaintext) > 0 {
		var blockSize int
		if len(plaintext) > encrypt_group_size {
			blockSize = encrypt_group_size
		} else {
			blockSize = len(plaintext)
		}
		encryptedBlock, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plaintext[:blockSize])
		if err != nil {
			return "", err
		}
		encryptedData = append(encryptedData, encryptedBlock...)
		plaintext = plaintext[blockSize:]
	}

	return fmt.Sprintf("%x\n", encryptedData), nil
}
