# go-cfdiclient

A Go client for the SAT (Servicio de Administración Tributaria, México) **Descarga Masiva de CFDI** web services. It lets a taxpayer — using their FIEL (e.firma) certificate and private key — authenticate against SAT, request bulk CFDI downloads (emitidos / recibidos), poll for completion, and download the resulting ZIP packages.

This is a Go port of [luisiturrios/python-cfdiclient](https://github.com/luisiturrios/python-cfdiclient). Behavior (XML shape, canonicalization, signatures) aims to be byte-identical with the Python client.

> SAT publishes the official service contract at <https://www.sat.gob.mx/aplicacion/operacion/32846/solicita-informacion-a-traves-del-servicio-de-descarga-masiva>. You are responsible for handling the FIEL credentials with which you authenticate — never commit real `.cer` / `.key` material.

## Features

- FIEL loading (`.cer` DER + encrypted PKCS#8 `.key`) with RFC extraction from the subject DN.
- Authentication against `Autenticacion.svc` → WRAP access token.
- Solicitud de descarga **Emitidos** and **Recibidos** (Metadata o CFDI).
- Verificación de solicitud (polling for package readiness).
- Descarga masiva (downloads the base64 ZIP payload from the SOAP envelope).
- Validación de CFDI vigente via `ConsultaCFDIService` (status + cancelability).
- Exclusive XML C14N 1.0 and `rsa-sha1` signing, matching the reference Python implementation.

## Installation

```bash
go get cfdiclient/cfdiclient
```

The module path is currently the local `cfdiclient`. Adjust `go.mod` and imports if you publish it under a hosted path.

Requirements:

- Go 1.23+
- A valid SAT FIEL (`.cer` + `.key` + passphrase) for the RFC you will query.

## Quickstart

The `cmd/ejemplo` binary runs the full happy path: authenticate → solicitar → verificar (loop) → descargar paquetes. It's both a demo and an integration smoke test.

```bash
go run ./cmd/ejemplo \
  -cer certificados/ejemploCer.cer \
  -key certificados/ejemploKey.key \
  -pass 12345678a \
  -from 2025-06-01 \
  -to   2025-06-02
```

Every flag is also overridable via env vars: `FIEL_CER`, `FIEL_KEY`, `FIEL_PASS`, `FIEL_RFC`, `FIEL_FROM`, `FIEL_TO`.

The sample FIEL in `certificados/` is SAT's public test certificate — it authenticates but cannot actually pull data for a real RFC. Swap it for your own to exercise the full flow.

## Minimal library usage

```go
package main

import (
    "log"
    "os"
    "time"

    "cfdiclient/cfdiclient"
)

func main() {
    cer, _ := os.ReadFile("fiel.cer")
    key, _ := os.ReadFile("fiel.key")

    fiel, err := cfdiclient.NewFiel(cer, key, "passphrase")
    if err != nil { log.Fatal(err) }

    auth, _ := cfdiclient.NewAutenticacion(fiel)
    token, err := auth.ObtenerToken(0) // 0 → default 300s
    if err != nil { log.Fatal(err) }

    req, _ := cfdiclient.NewSolicitaDescargaRecibidos(fiel)
    res, err := req.SolicitarDescarga(token, cfdiclient.SolicitudParams{
        RfcSolicitante:    fiel.RFC(),
        RfcReceptor:       fiel.RFC(),
        FechaInicial:      time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
        FechaFinal:        time.Date(2025, 6, 2, 0, 0, 0, 0, time.UTC),
        TipoSolicitud:     "Metadata",
        EstadoComprobante: "Todos",
    })
    if err != nil { log.Fatal(err) }
    log.Printf("solicitud: %+v", res)
}
```

See [`docs/usage.md`](docs/usage.md) for the verificación / descarga loop and validación.

## Project layout

```
.
├── cmd/ejemplo/            Runnable end-to-end example
├── cfdiclient/             Library package
│   ├── autenticacion.go    WRAP token acquisition
│   ├── solicita_emitidos.go / solicita_recibidos.go
│   ├── verifica.go         Poll for package readiness
│   ├── descarga.go         Paquete download (base64 ZIP)
│   ├── validacion.go       ConsultaCFDIService (estado, cancelable)
│   ├── signer.go           xmldsig Signature block over solicitud parent
│   ├── webservicerequest.go  Shared SOAP plumbing
│   ├── fiel.go             Cert/key + RFC extraction
│   ├── xml.go              Template loader, C14N, NS-aware XPath helpers
│   └── templates/          Embedded SOAP envelope templates (//go:embed)
├── certificados/           Public SAT sample FIEL (for demo only)
└── testdata/c14n/          Canonicalization parity fixtures
```

## Build & test

```bash
go build ./...
go test  ./...
```

The canonicalization tests under `cfdiclient/c14n_test.go` compare Go's output against fixtures captured from the Python reference to guard against drift.

## Documentation

- [`docs/usage.md`](docs/usage.md) — end-to-end flow, parameters, common pitfalls.
- [`docs/architecture.md`](docs/architecture.md) — how the package is organized, signing model, C14N notes.

## Credits

- Original Python implementation: [luisiturrios/python-cfdiclient](https://github.com/luisiturrios/python-cfdiclient).
- This port was AI-assisted; verify behavior in your own environment before production use.

## License

[GNU General Public License v3.0](LICENSE), matching the upstream [luisiturrios/python-cfdiclient](https://github.com/luisiturrios/python-cfdiclient) project.
