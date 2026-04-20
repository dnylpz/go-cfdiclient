package cfdiclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/beevik/etree"
)

type ValidacionResult struct {
	CodigoEstatus string
	EsCancelable  string
	Estado        string
}

type Validacion struct {
	verify  bool
	timeout time.Duration
}

func NewValidacion(verify bool, timeout time.Duration) *Validacion {
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	return &Validacion{verify: verify, timeout: timeout}
}

const (
	validacionSOAPURL    = "https://consultaqr.facturaelectronica.sat.gob.mx/ConsultaCFDIService.svc"
	validacionSOAPAction = "http://tempuri.org/IConsultaCFDIService/Consulta"
)

var validacionNSMap = map[string]string{
	"s": "http://schemas.xmlsoap.org/soap/envelope/",
	"t": "http://tempuri.org/",
	"a": "http://schemas.datacontract.org/2004/07/Sat.Cfdi.Negocio.ConsultaCfdi.Servicio",
}

var validacionFaultNSMap = map[string]string{
	"s": "http://schemas.xmlsoap.org/soap/envelope/",
}

func (v *Validacion) ObtenerEstado(rfcEmisor, rfcReceptor, total, uuid string) (*ValidacionResult, error) {
	body := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">` +
		`<soapenv:Header/>` +
		`<soapenv:Body>` +
		`<tem:Consulta>` +
		`<tem:expresionImpresa>` +
		`<![CDATA[?re=` + rfcEmisor + `&rr=` + rfcReceptor + `&tt=` + total + `&id=` + uuid + `]]>` +
		`</tem:expresionImpresa>` +
		`</tem:Consulta>` +
		`</soapenv:Body>` +
		`</soapenv:Envelope>`

	req, err := http.NewRequest(http.MethodPost, validacionSOAPURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml;charset="utf-8"`)
	req.Header.Set("Accept", "text/xml")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("SOAPAction", validacionSOAPAction)

	client := &http.Client{
		Timeout: v.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !v.verify},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	text := string(raw)

	if resp.StatusCode != http.StatusOK {
		if !strings.HasPrefix(text, "<s:Envelope") {
			return nil, fmt.Errorf("El webservice Autenticacion responde: %s", text)
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(raw); err != nil {
			return nil, fmt.Errorf("%s", text)
		}
		fault := findElement(doc.Root(), "s:Body/s:Fault/faultstring", validacionFaultNSMap)
		if fault != nil {
			return nil, fmt.Errorf("%s", fault.Text())
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, text)
	}
	if !strings.HasPrefix(text, "<s:Envelope") {
		return nil, fmt.Errorf("El webservice Autenticacion responde: %s", text)
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	root := doc.Root()

	pick := func(p string) string {
		el := findElement(root, p, validacionNSMap)
		if el == nil {
			return ""
		}
		return el.Text()
	}

	return &ValidacionResult{
		CodigoEstatus: pick("s:Body/t:ConsultaResponse/t:ConsultaResult/a:CodigoEstatus"),
		EsCancelable:  pick("s:Body/t:ConsultaResponse/t:ConsultaResult/a:EsCancelable"),
		Estado:        pick("s:Body/t:ConsultaResponse/t:ConsultaResult/a:Estado"),
	}, nil
}
