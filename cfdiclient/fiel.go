package cfdiclient

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/youmark/pkcs8"
)

type Fiel struct {
	cer    *x509.Certificate
	cerDER []byte
	key    *rsa.PrivateKey
	rfc    string
}

func NewFiel(cerDER, keyDER []byte, passphrase string) (*Fiel, error) {
	cer, err := x509.ParseCertificate(cerDER)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	parsedKey, err := pkcs8.ParsePKCS8PrivateKey(keyDER, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}

	rfc, err := rfcFromSubject(cer.RawSubject)
	if err != nil {
		return nil, fmt.Errorf("extract RFC: %w", err)
	}

	return &Fiel{cer: cer, cerDER: cerDER, key: rsaKey, rfc: rfc}, nil
}

// RFC returns the RFC encoded in the certificate's subject DN. SAT FIEL certs
// carry it in either x500UniqueIdentifier (persona física) or serialNumber
// (persona moral), usually as "RFC / CURP" for individuals.
func (f *Fiel) RFC() string {
	return f.rfc
}

func (f *Fiel) FirmarSHA1(data []byte) (string, error) {
	sum := sha1.Sum(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA1, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (f *Fiel) CerToBase64() string {
	return base64.StdEncoding.EncodeToString(f.cerDER)
}

func (f *Fiel) CerSerialNumber() string {
	return f.cer.SerialNumber.String()
}

// CerIssuer emits "SHORTNAME=value,SHORTNAME=value,..." preserving the
// RDN order from the certificate's raw issuer DN. This mirrors pyOpenSSL's
// X509Name.get_components() output used by the Python client.
func (f *Fiel) CerIssuer() (string, error) {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(f.cer.RawIssuer, &rdns); err != nil {
		return "", fmt.Errorf("unmarshal issuer: %w", err)
	}
	parts := make([]string, 0, len(rdns))
	for _, rdn := range rdns {
		for _, atv := range rdn {
			short := oidShortName(atv.Type)
			parts = append(parts, fmt.Sprintf("%s=%v", short, atv.Value))
		}
	}
	return strings.Join(parts, ","), nil
}

var rfcRegex = regexp.MustCompile(`^[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}$`)

// rfcFromSubject scans the cert's subject DN for an RFC, preferring
// x500UniqueIdentifier (2.5.4.45) and falling back to serialNumber (2.5.4.5).
// Values often take the form "RFC / CURP" — the first whitespace/slash token
// that matches the SAT RFC shape wins.
func rfcFromSubject(rawSubject []byte) (string, error) {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawSubject, &rdns); err != nil {
		return "", err
	}
	byOID := func(oid string) string {
		for _, rdn := range rdns {
			for _, atv := range rdn {
				if atv.Type.String() == oid {
					if s, ok := atv.Value.(string); ok {
						return s
					}
				}
			}
		}
		return ""
	}
	for _, oid := range []string{"2.5.4.45", "2.5.4.5"} {
		raw := byOID(oid)
		if raw == "" {
			continue
		}
		for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
			return r == ' ' || r == '/'
		}) {
			tok = strings.ToUpper(strings.TrimSpace(tok))
			if rfcRegex.MatchString(tok) {
				return tok, nil
			}
		}
	}
	return "", fmt.Errorf("RFC not found in certificate subject")
}

// oidShortName mirrors the short names OpenSSL (and thus pyOpenSSL) emits for
// X.509 name attributes. Unknown OIDs fall back to their dotted form, matching
// OpenSSL's OBJ_obj2txt behavior.
func oidShortName(oid asn1.ObjectIdentifier) string {
	key := oid.String()
	if name, ok := oidNames[key]; ok {
		return name
	}
	return key
}

var oidNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.13":                   "description",
	"2.5.4.14":                   "searchGuide",
	"2.5.4.15":                   "businessCategory",
	"2.5.4.16":                   "postalAddress",
	"2.5.4.17":                   "postalCode",
	"2.5.4.18":                   "postOfficeBox",
	"2.5.4.20":                   "telephoneNumber",
	"2.5.4.41":                   "name",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.45":                   "x500UniqueIdentifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1":  "UID",
}
