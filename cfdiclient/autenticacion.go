package cfdiclient

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"time"
)

const authDateTimeFormat = "2006-01-02T15:04:05.000Z"

var autenticacionExternalNS = map[string]string{
	"":  "http://DescargaMasivaTerceros.gob.mx",
	"s": "http://schemas.xmlsoap.org/soap/envelope/",
	"u": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	"o": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
}

type Autenticacion struct {
	ws *webServiceRequest
}

func NewAutenticacion(fiel *Fiel) (*Autenticacion, error) {
	ws, err := newWebServiceRequest(webServiceConfig{
		xmlName:     "autenticacion.xml",
		soapURL:     "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc",
		soapAction:  "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica",
		resultXPath: "s:Body/AutenticaResponse/AutenticaResult",
		externalNS:  autenticacionExternalNS,
	}, fiel, true, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &Autenticacion{ws: ws}, nil
}

// ObtenerToken requests a fresh WRAP access token. validFor sets the lifetime
// of the signed Timestamp; 0 uses the Python default of 300 seconds.
func (a *Autenticacion) ObtenerToken(validFor time.Duration) (string, error) {
	if validFor == 0 {
		validFor = 300 * time.Second
	}

	created := time.Now().UTC()
	expires := created.Add(validFor)
	createdStr := created.Format(authDateTimeFormat)
	expiresStr := expires.Format(authDateTimeFormat)

	root := a.ws.root
	ns := a.ws.cfg.internalNS

	if err := setElementText(root, "s:Header/o:Security/u:Timestamp/u:Created", ns, createdStr); err != nil {
		return "", err
	}
	if err := setElementText(root, "s:Header/o:Security/u:Timestamp/u:Expires", ns, expiresStr); err != nil {
		return "", err
	}
	if err := setElementText(root, "s:Header/o:Security/o:BinarySecurityToken", ns, a.ws.fiel.CerToBase64()); err != nil {
		return "", err
	}

	timestamp := findElement(root, "s:Header/o:Security/u:Timestamp", ns)
	if timestamp == nil {
		return "", fmt.Errorf("timestamp not found")
	}
	timestampBytes, err := canonicalize(timestamp)
	if err != nil {
		return "", err
	}
	tsSum := sha1.Sum(timestampBytes)
	tsDigest := base64.StdEncoding.EncodeToString(tsSum[:])

	if err := setElementText(root, "s:Header/o:Security/Signature/SignedInfo/Reference/DigestValue", ns, tsDigest); err != nil {
		return "", err
	}

	signedInfo := findElement(root, "s:Header/o:Security/Signature/SignedInfo", ns)
	if signedInfo == nil {
		return "", fmt.Errorf("signedInfo not found")
	}
	signedInfoBytes, err := canonicalize(signedInfo)
	if err != nil {
		return "", err
	}
	sigValue, err := a.ws.fiel.FirmarSHA1(signedInfoBytes)
	if err != nil {
		return "", err
	}
	if err := setElementText(root, "s:Header/o:Security/Signature/SignatureValue", ns, sigValue); err != nil {
		return "", err
	}

	result, err := a.ws.request("", nil)
	if err != nil {
		return "", err
	}
	return result.Text(), nil
}
