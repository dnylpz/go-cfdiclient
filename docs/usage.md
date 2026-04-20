# Usage guide

This document walks through the full SAT *Descarga Masiva de Terceros* flow and shows how each piece maps to code in the `cfdiclient` package.

The SAT flow has four steps:

1. **Autenticación** — trade your FIEL signature for a short-lived WRAP access token.
2. **Solicitud** — ask SAT to prepare a batch of CFDIs (emitidos or recibidos) for a date range.
3. **Verificación** — poll until the batch is ready and SAT hands you a list of package IDs.
4. **Descarga** — download each package (a base64-encoded ZIP) and write it to disk.

## 1. Load the FIEL

```go
cer, _ := os.ReadFile("fiel.cer")       // DER
key, _ := os.ReadFile("fiel.key")       // encrypted PKCS#8 DER
fiel, err := cfdiclient.NewFiel(cer, key, passphrase)
```

`NewFiel` parses the certificate, decrypts the private key, and extracts the RFC from the subject DN. It looks at `x500UniqueIdentifier` (2.5.4.45) first, then falls back to `serialNumber` (2.5.4.5). Values of the form `RFC / CURP` are tokenized — the first token that matches the SAT RFC shape wins.

```go
rfc := fiel.RFC()          // e.g. "AAA010101AAA"
```

## 2. Obtain a token

```go
auth, err := cfdiclient.NewAutenticacion(fiel)
token, err := auth.ObtenerToken(0)   // 0 = default 300s lifetime
```

`ObtenerToken(validFor)` stamps a `<u:Timestamp>` with `Created` = now UTC and `Expires` = now + `validFor`, signs the timestamp with the FIEL's RSA-SHA1 key, and POSTs the envelope to `Autenticacion.svc`. The returned string is the WRAP access token that must accompany every subsequent SOAP call.

Tokens expire. The `cmd/ejemplo` sample re-requests a token on every verificación poll to stay safe — do the same for long-running jobs.

## 3. Solicitar descarga

Two variants, same parameter struct:

```go
params := cfdiclient.SolicitudParams{
    RfcSolicitante:    fiel.RFC(),                        // required
    FechaInicial:      time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
    FechaFinal:        time.Date(2025, 6, 2, 0, 0, 0, 0, time.UTC),
    TipoSolicitud:     "Metadata",    // "Metadata" or "CFDI" (default "CFDI")
    EstadoComprobante: "Todos",       // "Vigente" | "Cancelado" | "Todos"
    // Optional filters:
    //   RfcEmisor, RfcReceptor, TipoComprobante, RfcACuentaTerceros,
    //   Complemento, UUID
}
```

For **recibidos** (CFDIs where you are the receptor):

```go
req, _  := cfdiclient.NewSolicitaDescargaRecibidos(fiel)
res, err := req.SolicitarDescarga(token, params)   // params.RfcReceptor = fiel.RFC()
```

For **emitidos** (CFDIs you issued):

```go
req, _  := cfdiclient.NewSolicitaDescargaEmitidos(fiel)
res, err := req.SolicitarDescarga(token, params)   // params.RfcEmisor = fiel.RFC() (optional)
```

`res` contains:

| Field | Meaning |
| --- | --- |
| `IdSolicitud` | UUID used to poll for this batch |
| `CodEstatus`  | `"5000"` indicates the solicitud was accepted |
| `Mensaje`     | Human-readable status |

## 4. Verificar la solicitud

Keep polling until SAT reports `EstadoSolicitud` ≥ 3.

```go
ver, _ := cfdiclient.NewVerificaSolicitudDescarga(fiel)
for {
    token, _ = auth.ObtenerToken(0)       // refresh; tokens expire
    v, err := ver.VerificarDescarga(token, rfc, res.IdSolicitud)
    if err != nil { log.Fatal(err) }

    estado, _ := strconv.Atoi(v.EstadoSolicitud)
    switch {
    case estado <= 2: // 0 token inválido, 1 aceptada, 2 en proceso
        time.Sleep(10 * time.Second)
        continue
    case estado >= 4: // 4 error, 5 rechazada, 6 vencida
        log.Fatal("solicitud failed:", v.Mensaje)
    }
    // estado == 3: terminada, v.Paquetes has the package IDs
    break
}
```

Reference values for `EstadoSolicitud`:

| Código | Significado |
| --- | --- |
| 0 | Token inválido |
| 1 | Aceptada |
| 2 | En proceso |
| 3 | Terminada |
| 4 | Error |
| 5 | Rechazada |
| 6 | Vencida |

## 5. Descargar los paquetes

```go
dm, _ := cfdiclient.NewDescargaMasiva(fiel)
for _, id := range v.Paquetes {
    d, err := dm.DescargarPaquete(token, rfc, id)
    if err != nil { log.Fatal(err) }

    zipBytes, _ := base64.StdEncoding.DecodeString(d.PaqueteB64)
    _ = os.WriteFile(id+".zip", zipBytes, 0o644)
}
```

`d.CodEstatus` + `d.Mensaje` come from the `h:respuesta` header alongside the payload; inspect them before trusting `PaqueteB64`.

## Validación individual de CFDI

Independent from the masivo flow — no token, no FIEL required:

```go
v := cfdiclient.NewValidacion(true, 15*time.Second)
r, err := v.ObtenerEstado(rfcEmisor, rfcReceptor, total, uuid)
// r.CodigoEstatus, r.Estado ("Vigente" | "Cancelado"), r.EsCancelable
```

`NewValidacion(verify, timeout)` — `verify=false` disables TLS certificate verification (don't use this in production; it exists for parity with environments where the Python reference disabled it).

## Common pitfalls

- **Wrong cert format.** The client expects the raw DER `.cer` and the encrypted PKCS#8 DER `.key` SAT ships. If you export to PEM, convert back before loading.
- **Wrong RFC case.** Internally everything is upper-cased; passing lower-case is fine.
- **Tokens expire in ~5 minutes.** Long verificación loops must refresh.
- **Date range too big.** SAT will accept the solicitud but eventually return `EstadoSolicitud=5` with a rejection reason in `Mensaje`.
- **Using the sample FIEL.** `certificados/ejemploCer.cer` is SAT's public test FIEL — it authenticates but has no data tied to it.
