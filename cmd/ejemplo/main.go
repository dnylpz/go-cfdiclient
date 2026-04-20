package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/dnylpz/go-cfdiclient/cfdiclient"
)

// Defaults point at the upstream sample FIEL shipped in certificados/.
const (
	defaultCer  = "certificados/ejemploCer.cer"
	defaultKey  = "certificados/ejemploKey.key"
	defaultPass = "12345678a"
	defaultFrom = "2025-06-01"
	defaultTo   = "2025-06-02"
)

// envOr returns the value of name when set, otherwise fallback. Lets every
// flag be overridden by FIEL_* env vars without repeating the pattern inline.
func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	cerPath := flag.String("cer", envOr("FIEL_CER", defaultCer), "path to FIEL .cer (DER). Env: FIEL_CER")
	keyPath := flag.String("key", envOr("FIEL_KEY", defaultKey), "path to FIEL .key (encrypted PKCS#8 DER). Env: FIEL_KEY")
	pass := flag.String("pass", envOr("FIEL_PASS", defaultPass), "FIEL key password. Env: FIEL_PASS")
	rfcFlag := flag.String("rfc", envOr("FIEL_RFC", ""), "solicitante RFC (defaults to the RFC in the FIEL cert). Env: FIEL_RFC")
	from := flag.String("from", envOr("FIEL_FROM", defaultFrom), "fecha inicial YYYY-MM-DD. Env: FIEL_FROM")
	to := flag.String("to", envOr("FIEL_TO", defaultTo), "fecha final YYYY-MM-DD. Env: FIEL_TO")
	flag.Parse()

	fechaInicial, err := time.Parse("2006-01-02", *from)
	if err != nil {
		log.Fatalf("invalid -from: %v", err)
	}
	fechaFinal, err := time.Parse("2006-01-02", *to)
	if err != nil {
		log.Fatalf("invalid -to: %v", err)
	}

	cerDER, err := os.ReadFile(*cerPath)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatal(err)
	}

	fiel, err := cfdiclient.NewFiel(cerDER, keyDER, *pass)
	if err != nil {
		log.Fatal(err)
	}

	rfc := *rfcFlag
	if rfc == "" {
		rfc = fiel.RFC()
	}
	fmt.Println("RFC:", rfc)

	auth, err := cfdiclient.NewAutenticacion(fiel)
	if err != nil {
		log.Fatal(err)
	}
	token, err := auth.ObtenerToken(0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("TOKEN:", token)

	descarga, err := cfdiclient.NewSolicitaDescargaRecibidos(fiel)
	if err != nil {
		log.Fatal(err)
	}
	solicitud, err := descarga.SolicitarDescarga(token, cfdiclient.SolicitudParams{
		RfcSolicitante:    rfc,
		FechaInicial:      fechaInicial,
		FechaFinal:        fechaFinal,
		RfcReceptor:       rfc,
		TipoSolicitud:     "Metadata",
		EstadoComprobante: "Todos",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("solicitar_descarga: %+v\n", solicitud)

	if solicitud.CodEstatus != "5000" {
		os.Exit(1)
	}

	for {
		token, err = auth.ObtenerToken(0)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("TOKEN:", token)

		verificacion, err := cfdiclient.NewVerificaSolicitudDescarga(fiel)
		if err != nil {
			log.Fatal(err)
		}
		v, err := verificacion.VerificarDescarga(token, rfc, solicitud.IdSolicitud)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("verificar_descarga: %+v\n", v)

		estado, err := strconv.Atoi(v.EstadoSolicitud)
		if err != nil {
			log.Fatal(err)
		}

		// 0 token inválido, 1 aceptada, 2 en proceso, 3 terminada,
		// 4 error, 5 rechazada, 6 vencida.
		switch {
		case estado <= 2:
			time.Sleep(10 * time.Second)
			continue
		case estado >= 4:
			fmt.Println("ERROR:", estado)
			return
		}

		for _, paquete := range v.Paquetes {
			dm, err := cfdiclient.NewDescargaMasiva(fiel)
			if err != nil {
				log.Fatal(err)
			}
			d, err := dm.DescargarPaquete(token, rfc, paquete)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("PAQUETE:", paquete)
			zipBytes, err := base64.StdEncoding.DecodeString(d.PaqueteB64)
			if err != nil {
				log.Fatal(err)
			}
			if err := os.WriteFile(paquete+".zip", zipBytes, 0o644); err != nil {
				log.Fatal(err)
			}
		}
		return
	}
}
