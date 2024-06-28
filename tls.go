package certs

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"

	"github.com/EnsurityTechnologies/wraperr"
	"software.sslmate.com/src/go-pkcs12"
)

var ErrInvalidTLSParams = errors.New("Nnvalid TLS parameters")

// TLSVersion maps the tls_min_version configuration to the internal value
var TLSVersion = map[string]uint16{
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
	"tls13": tls.VersionTLS13,
}

// TLSDefaultVersion default min version
var TLSDefaultVersion uint16 = tls.VersionTLS12

// TLSCipher maps the TLS cipher suite names to the internal cipher suite code.
var TLSCipher = map[string]uint16{
	"TLS_RSA_WITH_RC4_128_SHA":                tls.TLS_RSA_WITH_RC4_128_SHA,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":           tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":        tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":          tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":     tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	"TLS_AES_128_GCM_SHA256":                  tls.TLS_AES_128_GCM_SHA256,
	"TLS_AES_256_GCM_SHA384":                  tls.TLS_AES_256_GCM_SHA384,
	"TLS_CHACHA20_POLY1305_SHA256":            tls.TLS_CHACHA20_POLY1305_SHA256,
}

// TLSDefaultCipher maps the TLS cipher suite names to the internal cipher suite code.
var TLSDefaultCipher = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
}

// ParseCiphers parse ciphersuites from the comma-separated string into recognized slice
func ParseCiphers(cipherStr string) ([]uint16, error) {
	suites := []uint16{}
	ciphers := parseStringSlice(cipherStr, ",")
	for _, cipher := range ciphers {
		if v, ok := TLSCipher[cipher]; ok {
			suites = append(suites, v)
		} else {
			return suites, fmt.Errorf("unsupported cipher %q", cipher)
		}
	}

	return suites, nil
}

// TLSCertificate tls certificate struct
type TLSCertificate struct {
	sync.RWMutex

	cert       *tls.Certificate
	pfx        bool
	certFile   string
	keyFile    string
	passphrase string
}

// ReloadFunc are functions that are called when a reload is requested
type ReloadFunc func() error

// NewTLSCertificate Create new TLS Certificate
func NewTLSCertificate(certFile, keyFile, passphrase string) *TLSCertificate {
	return &TLSCertificate{
		certFile:   certFile,
		keyFile:    keyFile,
		passphrase: passphrase,
	}
}

// NewTLSCertificate Create new TLS Certificate
func NewTLSCertificateFromPFX(certFile, passphrase string) *TLSCertificate {
	return &TLSCertificate{
		pfx:        true,
		certFile:   certFile,
		passphrase: passphrase,
	}
}

// ParseStringSlice parses a `sep`-separated list of strings into a
// []string with surrounding whitespace removed.
//
// The output will always be a valid slice but may be of length zero.
func parseStringSlice(input string, sep string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return []string{}
	}

	splitStr := strings.Split(input, sep)
	ret := make([]string, len(splitStr))
	for i, val := range splitStr {
		ret[i] = strings.TrimSpace(val)
	}

	return ret
}

func (tc *TLSCertificate) reloadCert() error {
	certPEMBlock, err := ioutil.ReadFile(tc.certFile)
	if err != nil {
		return err
	}
	keyPEMBlock, err := ioutil.ReadFile(tc.keyFile)
	if err != nil {
		return err
	}

	// Check for encrypted pem block
	keyBlock, _ := pem.Decode(keyPEMBlock)
	if keyBlock == nil {
		return errors.New("decoded PEM is blank")
	}

	if x509.IsEncryptedPEMBlock(keyBlock) {
		keyBlock.Bytes, err = x509.DecryptPEMBlock(keyBlock, []byte(tc.passphrase))
		if err != nil {
			return wraperr.Wrapf(err, "Decrypting PEM block failed")
		}
		keyPEMBlock = pem.EncodeToMemory(keyBlock)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}

	tc.Lock()
	defer tc.Unlock()

	tc.cert = &cert

	return nil
}

func (tc *TLSCertificate) reloadPFXCert() error {
	cd, err := ioutil.ReadFile(tc.certFile)
	if err != nil {
		return err
	}

	// Extract the Primary key and certificate from decoding
	key, ct, err := pkcs12.Decode(cd, tc.passphrase)
	if err != nil && err.Error() != "pkcs12: expected exactly two safe bags in the PFX PDU" {
		return err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ct.Raw,
	}
	certPEMBlock := pem.EncodeToMemory(certBlock)

	//  // Convert the private key to ASN.1 DER encoded form
	//  privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	var privateKeyDER []byte
	switch ct.PublicKey.(type) {
	case *rsa.PublicKey:
		pk := key.(*rsa.PrivateKey)
		privateKeyDER = x509.MarshalPKCS1PrivateKey(pk)
	case *ecdsa.PublicKey:
		pk := key.(*ecdsa.PrivateKey)
		privateKeyDER, err = x509.MarshalECPrivateKey(pk)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("certificate algorithm is not supported")
	}

	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}
	keyPEMBlock := pem.EncodeToMemory(keyBlock)
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return err
	}
	tc.Lock()
	defer tc.Unlock()
	tc.cert = &cert
	return nil
}

// Reload Reload the certificate
func (tc *TLSCertificate) Reload() error {
	if tc.pfx {
		return tc.reloadPFXCert()
	} else {
		return tc.reloadCert()
	}
}

// GetCertificate GetCertificate method
func (tc *TLSCertificate) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	tc.RLock()
	defer tc.RUnlock()

	if tc.cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}

	return tc.cert, nil
}

// GetCipherName returns the name of a given cipher suite code or an error if the
// given cipher is unsupported.
func GetCipherName(cipher uint16) (string, error) {
	for cipherStr, cipherCode := range TLSCipher {
		if cipherCode == cipher {
			return cipherStr, nil
		}
	}
	return "", fmt.Errorf("unsupported cipher %d", cipher)
}
