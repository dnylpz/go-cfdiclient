package cfdiclient

import (
	"strings"
	"time"
)

type SolicitaDescargaRecibidos struct {
	ws *webServiceRequest
}

func NewSolicitaDescargaRecibidos(fiel *Fiel) (*SolicitaDescargaRecibidos, error) {
	ws, err := newWebServiceRequest(webServiceConfig{
		xmlName:        "solicitadescargaRecibidos.xml",
		soapURL:        "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc",
		soapAction:     "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescargaRecibidos",
		solicitudXPath: "s:Body/des:SolicitaDescargaRecibidos/des:solicitud",
		resultXPath:    "s:Body/SolicitaDescargaRecibidosResponse/SolicitaDescargaRecibidosResult",
	}, fiel, true, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &SolicitaDescargaRecibidos{ws: ws}, nil
}

func (s *SolicitaDescargaRecibidos) SolicitarDescarga(token string, p SolicitudParams) (*SolicitudResult, error) {
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
		{Name: "RfcReceptor", Value: p.RfcReceptor},
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
