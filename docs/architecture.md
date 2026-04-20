# Architecture

`go-cfdiclient` is a faithful Go port of [luisiturrios/python-cfdiclient](https://github.com/luisiturrios/python-cfdiclient). The design goal is byte-for-byte parity with what the Python client emits on the wire — any divergence is a bug, because SAT validates the enveloped XML signature.

## High-level flow

```
  FIEL (.cer + .key)
        │
        ▼
  Autenticacion ───► WRAP access token
        │
        ▼
  SolicitaDescarga{Emitidos,Recibidos} ──► IdSolicitud
        │
        ▼
  VerificaSolicitudDescarga ──(loop)──► [Paquetes...]
        │
        ▼
  DescargaMasiva ──► base64 ZIP per paquete
```

Each box corresponds to a top-level file in `cfdiclient/`. They share a single SOAP plumbing layer (`webservicerequest.go`) and a common signing helper (`signer.go`).

## Package layout

| File | Responsibility |
| --- | --- |
| `fiel.go` | Parse the FIEL cert + encrypted PKCS#8 key, extract RFC, expose RSA-SHA1 signing and a few derived fields (cert b64, issuer DN, serial). |
| `autenticacion.go` | Build the WS-Security timestamp envelope, sign the `<u:Timestamp>`, POST it, return the WRAP token. |
| `webservicerequest.go` | Shared SOAP machinery: load template, set solicitud attributes, invoke `Signer`, canonicalize, POST, parse fault / result. |
| `signer.go` | Populate the `signer.xml` template (digest, signature, X509 info) and graft it onto the target element. |
| `solicita_emitidos.go`, `solicita_recibidos.go` | Configure the WS request for each variant and marshal `SolicitudParams` into attributes. |
| `verifica.go` | Poll endpoint; extract `EstadoSolicitud` + `IdsPaquetes` children. |
| `descarga.go` | Fetch a package; pull base64 payload from the body and status from the `h:respuesta` header sibling. |
| `validacion.go` | Independent `ConsultaCFDIService` client (no FIEL, no token). |
| `xml.go` | Template loader, whitespace-stripping, namespace-aware XPath helper, and the canonicalizer. |
| `templates.go` | `//go:embed templates/*.xml` — SOAP envelopes ship inside the binary. |
| `templates/*.xml` | Verbatim copies of the Python templates. Keep them byte-identical to upstream. |

## Signing model

The SAT services use a specific flavor of XML-DSig:

- **Canonicalization:** Exclusive C14N 1.0, no comments (`http://www.w3.org/2001/10/xml-exc-c14n#`).
- **Signature method:** RSA-SHA1 (`http://www.w3.org/2000/09/xmldsig#rsa-sha1`).
- **Digest method:** SHA1 (`http://www.w3.org/2000/09/xmldsig#sha1`).
- **Reference:** empty `URI=""` — the digest is taken over the canonicalized *parent* of the solicitud element, not the whole document. This is non-obvious and mirrors the Python client.

`Signer.Sign(element)`:

1. Canonicalize `element.Parent()`, SHA1 it, base64-encode → `DigestValue`.
2. Canonicalize the populated `SignedInfo`, RSA-SHA1 it with the FIEL key → `SignatureValue`.
3. Fill `KeyInfo/X509Data` with the cert (base64 DER), issuer DN, and serial.
4. Append the complete `<Signature>` subtree under `element`.

Autenticación follows the same shape but the reference target is the `<u:Timestamp>`, so `autenticacion.go` does the digest/signing inline rather than routing through `Signer`.

## Canonicalization parity

Exclusive C14N is sensitive to:

- **Whitespace-only text nodes between elements.** lxml with `remove_blank_text=True` strips these; we replicate that in `stripBlankText` (`xml.go`). Leaf elements with meaningful text are left alone.
- **Inherited `xmlns` declarations.** `goxmldsig`'s exclusive C14N transform does not walk ancestors to collect namespaces. We pre-detach the element using `etreeutils.NSBuildParentContext` + `NSDetatch`, which annotates the subtree with the ancestor NS context. Exclusive C14N then prunes whichever declarations are not visibly utilized — matching lxml's subtree C14N behavior.

If a canonicalization test under `testdata/c14n/` starts failing, the fix is almost always in `canonicalize` or `stripBlankText`, not in the template.

## Namespace handling

There are two namespace maps (`xml.go`):

- `internalNSMap` — prefixes we use to *author* the request envelope. Notably `""` is bound to the XML-DSig namespace, because the signer's template has unprefixed elements (`Signature`, `SignedInfo`, …) that live in `http://www.w3.org/2000/09/xmldsig#`.
- `externalNSMap` — prefixes we use to *read* SAT responses. Here `""` is bound to the SAT namespace, because response elements (`AutenticaResult`, `Paquete`, …) are unprefixed in that namespace.

`findElement(root, xpath, nsmap)` resolves steps like `s:Body/des:SolicitaDescargaEmitidosResponse/...` by splitting on `/`, then on `:`, and using the nsmap to translate prefixes to URIs. It matches elements by `{namespace-uri, local-name}` rather than by prefix string — prefix choices on the wire can vary between SOAP stacks.

## Error surfacing

- HTTP non-2xx with a SOAP fault → we extract `s:Body/s:Fault/faultstring` and surface its text verbatim.
- Malformed response → we return the raw body as the error message so it lands in logs for diagnosis.
- Missing expected element at `resultXPath` → explicit `result not found at <path>` error.

There is intentionally no retry logic or exponential backoff at this layer — callers own their polling cadence (see `cmd/ejemplo/main.go`).

## What is NOT in this client

- No scheduling / orchestration.
- No ZIP extraction or CFDI XML parsing — callers handle the downloaded `.zip` themselves.
- No persistence of tokens or solicitud IDs.
- No rate limiting.

These are deliberate: the package is a thin, mechanical wrapper over the SAT SOAP contract. Higher-level workflow belongs in your application.
