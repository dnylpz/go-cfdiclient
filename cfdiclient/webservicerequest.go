package cfdiclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/beevik/etree"
)

// RequestArg is a single name/value pair applied to the solicitud element.
// For single-valued attributes Multi is nil and Value is used. For the
// RfcReceptores list pattern, Multi is populated and Name is "RfcReceptores".
type RequestArg struct {
	Name  string
	Value string
	Multi []string
}

type webServiceConfig struct {
	xmlName        string
	soapURL        string
	soapAction     string
	solicitudXPath string
	resultXPath    string
	internalNS     map[string]string
	externalNS     map[string]string
}

type webServiceRequest struct {
	cfg     webServiceConfig
	fiel    *Fiel
	signer  *Signer
	verify  bool
	timeout time.Duration
	doc     *etree.Document
	root    *etree.Element
}

func newWebServiceRequest(cfg webServiceConfig, fiel *Fiel, verify bool, timeout time.Duration) (*webServiceRequest, error) {
	doc, err := loadTemplate(cfg.xmlName)
	if err != nil {
		return nil, err
	}
	signer, err := NewSigner(fiel)
	if err != nil {
		return nil, err
	}
	if cfg.internalNS == nil {
		cfg.internalNS = internalNSMap
	}
	if cfg.externalNS == nil {
		cfg.externalNS = externalNSMap
	}
	return &webServiceRequest{
		cfg:     cfg,
		fiel:    fiel,
		signer:  signer,
		verify:  verify,
		timeout: timeout,
		doc:     doc,
		root:    doc.Root(),
	}, nil
}

func (w *webServiceRequest) headers(token string) http.Header {
	h := http.Header{}
	h.Set("Content-Type", `text/xml;charset="utf-8"`)
	h.Set("Accept", "text/xml")
	h.Set("Cache-Control", "no-cache")
	h.Set("SOAPAction", w.cfg.soapAction)
	if token != "" {
		h.Set("Authorization", fmt.Sprintf(`WRAP access_token="%s"`, token))
	} else {
		h.Set("Authorization", "")
	}
	return h
}

// setRequestArguments mirrors webservicerequest.set_request_arguments — set
// attributes on the solicitud element and special-case RfcReceptores (which
// populates a child element rather than an attribute).
func (w *webServiceRequest) setRequestArguments(args []RequestArg) (*etree.Element, error) {
	solicitud := findElement(w.root, w.cfg.solicitudXPath, w.cfg.internalNS)
	if solicitud == nil {
		return nil, fmt.Errorf("solicitud not found at %s", w.cfg.solicitudXPath)
	}
	for _, arg := range args {
		if arg.Name == "RfcReceptores" {
			if len(arg.Multi) > 0 {
				// Only the first receptor is populated, matching the Python TODO.
				if err := setElementText(
					w.root,
					"s:Body/des:SolicitaDescargaEmitidos/des:solicitud/des:RfcReceptores/des:RfcReceptor",
					w.cfg.internalNS,
					arg.Multi[0],
				); err != nil {
					return nil, err
				}
			}
			continue
		}
		if arg.Value != "" {
			solicitud.CreateAttr(arg.Name, arg.Value)
		}
	}
	return solicitud, nil
}

// request serializes the envelope (signing when arguments are present),
// POSTs to the SOAP endpoint, and returns the element at resultXPath.
func (w *webServiceRequest) request(token string, args []RequestArg) (*etree.Element, error) {
	if args != nil {
		solicitud, err := w.setRequestArguments(args)
		if err != nil {
			return nil, err
		}
		if err := w.signer.Sign(solicitud); err != nil {
			return nil, err
		}
	}

	body, err := canonicalize(w.root)
	if err != nil {
		return nil, fmt.Errorf("c14n envelope: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.cfg.soapURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header = w.headers(token)

	client := &http.Client{
		Timeout: w.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !w.verify},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	respDoc := etree.NewDocument()
	if err := respDoc.ReadFromBytes(respBytes); err != nil {
		return nil, fmt.Errorf("%s", string(respBytes))
	}

	if resp.StatusCode != http.StatusOK {
		fault := findElement(respDoc.Root(), "s:Body/s:Fault/faultstring", w.cfg.externalNS)
		if fault != nil {
			return nil, fmt.Errorf("%s", fault.Text())
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBytes))
	}

	result := findElement(respDoc.Root(), w.cfg.resultXPath, w.cfg.externalNS)
	if result == nil {
		return nil, fmt.Errorf("result not found at %s", w.cfg.resultXPath)
	}
	return result, nil
}
