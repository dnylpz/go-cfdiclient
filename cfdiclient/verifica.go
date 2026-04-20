package cfdiclient

import (
	"strings"
	"time"
)

type VerificaResult struct {
	CodEstatus            string
	EstadoSolicitud       string
	CodigoEstadoSolicitud string
	NumeroCFDIs           string
	Mensaje               string
	Paquetes              []string
}

type VerificaSolicitudDescarga struct {
	ws *webServiceRequest
}

func NewVerificaSolicitudDescarga(fiel *Fiel) (*VerificaSolicitudDescarga, error) {
	ws, err := newWebServiceRequest(webServiceConfig{
		xmlName:        "verificasolicituddescarga.xml",
		soapURL:        "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc",
		soapAction:     "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga",
		solicitudXPath: "s:Body/des:VerificaSolicitudDescarga/des:solicitud",
		resultXPath:    "s:Body/VerificaSolicitudDescargaResponse/VerificaSolicitudDescargaResult",
	}, fiel, true, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &VerificaSolicitudDescarga{ws: ws}, nil
}

func (v *VerificaSolicitudDescarga) VerificarDescarga(token, rfcSolicitante, idSolicitud string) (*VerificaResult, error) {
	args := []RequestArg{
		{Name: "RfcSolicitante", Value: strings.ToUpper(rfcSolicitante)},
		{Name: "IdSolicitud", Value: idSolicitud},
	}
	result, err := v.ws.request(token, args)
	if err != nil {
		return nil, err
	}

	satNS := "http://DescargaMasivaTerceros.sat.gob.mx"
	paquetes := []string{}
	for _, el := range iterByNS(result, satNS, "IdsPaquetes") {
		paquetes = append(paquetes, el.Text())
	}

	return &VerificaResult{
		CodEstatus:            result.SelectAttrValue("CodEstatus", ""),
		EstadoSolicitud:       result.SelectAttrValue("EstadoSolicitud", ""),
		CodigoEstadoSolicitud: result.SelectAttrValue("CodigoEstadoSolicitud", ""),
		NumeroCFDIs:           result.SelectAttrValue("NumeroCFDIs", ""),
		Mensaje:               result.SelectAttrValue("Mensaje", ""),
		Paquetes:              paquetes,
	}, nil
}
