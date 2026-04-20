package cfdiclient

import (
	"strings"
	"time"
)

const dateTimeFormat = "2006-01-02T15:04:05"

type SolicitudParams struct {
	RfcSolicitante    string
	FechaInicial      time.Time
	FechaFinal        time.Time
	RfcEmisor         string
	RfcReceptor       string
	TipoSolicitud     string // defaults to "CFDI"
	TipoComprobante   string
	EstadoComprobante string
	RfcACuentaTerceros string
	Complemento       string
	UUID              string
}

type SolicitudResult struct {
	IdSolicitud string
	CodEstatus  string
	Mensaje     string
}

type SolicitaDescargaEmitidos struct {
	ws *webServiceRequest
}

func NewSolicitaDescargaEmitidos(fiel *Fiel) (*SolicitaDescargaEmitidos, error) {
	ws, err := newWebServiceRequest(webServiceConfig{
		xmlName:        "solicitadescargaEmitidos.xml",
		soapURL:        "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc",
		soapAction:     "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaEmitidos",
		solicitudXPath: "s:Body/des:SolicitaDescargaEmitidos/des:solicitud",
		resultXPath:    "s:Body/SolicitaDescargaEmitidosResponse/SolicitaDescargaEmitidosResult",
	}, fiel, true, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &SolicitaDescargaEmitidos{ws: ws}, nil
}

func (s *SolicitaDescargaEmitidos) SolicitarDescarga(token string, p SolicitudParams) (*SolicitudResult, error) {
	tipo := p.TipoSolicitud
	if tipo == "" {
		tipo = "CFDI"
	}
	args := []RequestArg{
		{Name: "RfcSolicitante", Value: strings.ToUpper(p.RfcSolicitante)},
		{Name: "FechaFinal", Value: p.FechaFinal.Format(dateTimeFormat)},
		{Name: "FechaInicial", Value: p.FechaInicial.Format(dateTimeFormat)},
		{Name: "TipoSolicitud", Value: tipo},
		{Name: "TipoComprobante", Value: p.TipoComprobante},
		{Name: "EstadoComprobante", Value: p.EstadoComprobante},
		{Name: "RfcACuentaTerceros", Value: p.RfcACuentaTerceros},
		{Name: "Complemento", Value: p.Complemento},
		{Name: "UUID", Value: p.UUID},
	}
	if p.RfcEmisor != "" {
		args = append(args, RequestArg{Name: "RfcEmisor", Value: strings.ToUpper(p.RfcEmisor)})
	}
	if p.RfcReceptor != "" {
		args = append(args, RequestArg{Name: "RfcReceptores", Multi: []string{strings.ToUpper(p.RfcReceptor)}})
	}

	result, err := s.ws.request(token, args)
	if err != nil {
		return nil, err
	}
	return &SolicitudResult{
		IdSolicitud: result.SelectAttrValue("IdSolicitud", ""),
		CodEstatus:  result.SelectAttrValue("CodEstatus", ""),
		Mensaje:     result.SelectAttrValue("Mensaje", ""),
	}, nil
}
