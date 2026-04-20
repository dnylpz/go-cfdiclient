package cfdiclient

import (
	"strings"
	"time"
)

type DescargaResult struct {
	CodEstatus string
	Mensaje    string
	PaqueteB64 string
}

type DescargaMasiva struct {
	ws *webServiceRequest
}

func NewDescargaMasiva(fiel *Fiel) (*DescargaMasiva, error) {
	ws, err := newWebServiceRequest(webServiceConfig{
		xmlName:        "descargamasiva.xml",
		soapURL:        "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc",
		soapAction:     "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar",
		solicitudXPath: "s:Body/des:PeticionDescargaMasivaTercerosEntrada/des:peticionDescarga",
		resultXPath:    "s:Body/RespuestaDescargaMasivaTercerosSalida/Paquete",
	}, fiel, true, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return &DescargaMasiva{ws: ws}, nil
}

func (d *DescargaMasiva) DescargarPaquete(token, rfcSolicitante, idPaquete string) (*DescargaResult, error) {
	args := []RequestArg{
		{Name: "RfcSolicitante", Value: strings.ToUpper(rfcSolicitante)},
		{Name: "IdPaquete", Value: idPaquete},
	}
	result, err := d.ws.request(token, args)
	if err != nil {
		return nil, err
	}

	// Walk up to the envelope root to locate the respuesta sibling in the header.
	root := result
	for root.Parent() != nil {
		root = root.Parent()
	}
	respuesta := findElement(root, "s:Header/h:respuesta", externalNSMap)

	out := &DescargaResult{PaqueteB64: result.Text()}
	if respuesta != nil {
		out.CodEstatus = respuesta.SelectAttrValue("CodEstatus", "")
		out.Mensaje = respuesta.SelectAttrValue("Mensaje", "")
	}
	return out, nil
}
