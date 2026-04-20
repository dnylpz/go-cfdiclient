package cfdiclient

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"

	"github.com/beevik/etree"
)

// Signer mirrors the Python Signer. It owns a signer.xml template that gets
// populated with digest/signature values, then appended into the target
// element.
type Signer struct {
	fiel     *Fiel
	template *etree.Document
	root     *etree.Element
}

func NewSigner(fiel *Fiel) (*Signer, error) {
	tmpl, err := loadTemplate("signer.xml")
	if err != nil {
		return nil, err
	}
	return &Signer{fiel: fiel, template: tmpl, root: tmpl.Root()}, nil
}

// Sign populates the signer's Signature template using the digest of
// element.Parent() and appends the Signature element into element. This
// matches the Python behavior: the reference (no URI, implicit whole-doc) is
// the canonicalized parent of the solicitud element.
func (s *Signer) Sign(element *etree.Element) error {
	parent := element.Parent()
	if parent == nil {
		return fmt.Errorf("sign: element has no parent")
	}

	parentBytes, err := canonicalize(parent)
	if err != nil {
		return fmt.Errorf("c14n parent: %w", err)
	}
	sum := sha1.Sum(parentBytes)
	digestB64 := base64.StdEncoding.EncodeToString(sum[:])

	if err := setElementText(s.root, "SignedInfo/Reference/DigestValue", internalNSMap, digestB64); err != nil {
		return err
	}

	signedInfo := findElement(s.root, "SignedInfo", internalNSMap)
	if signedInfo == nil {
		return fmt.Errorf("sign: SignedInfo not found in template")
	}
	signedInfoBytes, err := canonicalize(signedInfo)
	if err != nil {
		return fmt.Errorf("c14n SignedInfo: %w", err)
	}
	sigValue, err := s.fiel.FirmarSHA1(signedInfoBytes)
	if err != nil {
		return err
	}
	if err := setElementText(s.root, "SignatureValue", internalNSMap, sigValue); err != nil {
		return err
	}

	issuer, err := s.fiel.CerIssuer()
	if err != nil {
		return err
	}
	if err := setElementText(s.root, "KeyInfo/X509Data/X509Certificate", internalNSMap, s.fiel.CerToBase64()); err != nil {
		return err
	}
	if err := setElementText(s.root, "KeyInfo/X509Data/X509IssuerSerial/X509IssuerName", internalNSMap, issuer); err != nil {
		return err
	}
	if err := setElementText(s.root, "KeyInfo/X509Data/X509IssuerSerial/X509SerialNumber", internalNSMap, s.fiel.CerSerialNumber()); err != nil {
		return err
	}

	element.AddChild(s.root.Copy())
	return nil
}
