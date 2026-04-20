package cfdiclient

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// These constants must stay in lockstep with python-cfdiclient/tools/dump_c14n.py.
const (
	testRFC          = "ESI920427886"
	testFechaInicial = "2025-06-01T00:00:00"
	testFechaFinal   = "2025-06-02T00:00:00"
	testIDSolicitud  = "11111111-2222-3333-4444-555555555555"
	testIDPaquete    = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE_01"
	testCreated      = "2025-01-01T00:00:00.000Z"
	testExpires      = "2025-01-01T00:05:00.000Z"
)

func fixturePath(name string) string {
	return filepath.Join("..", "testdata", "c14n", name+".py.bin")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath(name))
	if err != nil {
		t.Fatalf(
			"fixture %q missing — run:\n  python3 python-cfdiclient/tools/dump_c14n.py\n(err: %v)",
			name, err,
		)
	}
	return data
}

// assertParity compares got against the .py.bin fixture. On mismatch it writes
// the Go bytes to a .go.bin sibling and prints the diff command to run.
func assertParity(t *testing.T, name string, got []byte) {
	t.Helper()
	want := loadFixture(t, name)
	if bytes.Equal(got, want) {
		return
	}
	goPath := filepath.Join("..", "testdata", "c14n", name+".go.bin")
	if err := os.WriteFile(goPath, got, 0o644); err != nil {
		t.Logf("write %s: %v", goPath, err)
	}
	t.Fatalf(
		"c14n mismatch for %s: py=%d bytes, go=%d bytes\n  diff %s %s",
		name, len(want), len(got), fixturePath(name), goPath,
	)
}

// signedInfoBytes reproduces the Go Signer's SignedInfo canonicalization: load
// signer.xml, set DigestValue = b64(sha1(parentBytes)), canonicalize SignedInfo
// while it is still inside the signer template.
func signedInfoBytes(t *testing.T, parentBytes []byte) []byte {
	t.Helper()
	doc, err := loadTemplate("signer.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	sum := sha1.Sum(parentBytes)
	if err := setElementText(root, "SignedInfo/Reference/DigestValue", internalNSMap,
		base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	si := findElement(root, "SignedInfo", internalNSMap)
	if si == nil {
		t.Fatal("SignedInfo not found")
	}
	out, err := canonicalize(si)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestC14N_AuthTimestamp(t *testing.T) {
	doc, err := loadTemplate("autenticacion.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	must(t, setElementText(root, "s:Header/o:Security/u:Timestamp/u:Created", internalNSMap, testCreated))
	must(t, setElementText(root, "s:Header/o:Security/u:Timestamp/u:Expires", internalNSMap, testExpires))

	ts := findElement(root, "s:Header/o:Security/u:Timestamp", internalNSMap)
	if ts == nil {
		t.Fatal("timestamp not found")
	}
	got, err := canonicalize(ts)
	if err != nil {
		t.Fatal(err)
	}
	assertParity(t, "auth_timestamp", got)
}

func TestC14N_Emitidos(t *testing.T) {
	doc, err := loadTemplate("solicitadescargaEmitidos.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	solicitud := findElement(root, "s:Body/des:SolicitaDescargaEmitidos/des:solicitud", internalNSMap)
	if solicitud == nil {
		t.Fatal("solicitud not found")
	}
	solicitud.CreateAttr("RfcSolicitante", testRFC)
	solicitud.CreateAttr("FechaFinal", testFechaFinal)
	solicitud.CreateAttr("FechaInicial", testFechaInicial)
	solicitud.CreateAttr("TipoSolicitud", "CFDI")
	solicitud.CreateAttr("RfcEmisor", testRFC)
	must(t, setElementText(root,
		"s:Body/des:SolicitaDescargaEmitidos/des:solicitud/des:RfcReceptores/des:RfcReceptor",
		internalNSMap, testRFC))

	parent := solicitud.Parent()
	parentBytes, err := canonicalize(parent)
	if err != nil {
		t.Fatal(err)
	}
	assertParity(t, "emitidos_parent", parentBytes)
	assertParity(t, "emitidos_signedinfo", signedInfoBytes(t, parentBytes))
}

func TestC14N_Recibidos(t *testing.T) {
	doc, err := loadTemplate("solicitadescargaRecibidos.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	solicitud := findElement(root, "s:Body/des:SolicitaDescargaRecibidos/des:solicitud", internalNSMap)
	if solicitud == nil {
		t.Fatal("solicitud not found")
	}
	solicitud.CreateAttr("RfcSolicitante", testRFC)
	solicitud.CreateAttr("FechaFinal", testFechaFinal)
	solicitud.CreateAttr("FechaInicial", testFechaInicial)
	solicitud.CreateAttr("TipoSolicitud", "Metadata")
	solicitud.CreateAttr("EstadoComprobante", "Todos")
	solicitud.CreateAttr("RfcReceptor", testRFC)

	parent := solicitud.Parent()
	parentBytes, err := canonicalize(parent)
	if err != nil {
		t.Fatal(err)
	}
	assertParity(t, "recibidos_parent", parentBytes)
	assertParity(t, "recibidos_signedinfo", signedInfoBytes(t, parentBytes))
}

func TestC14N_Verifica(t *testing.T) {
	doc, err := loadTemplate("verificasolicituddescarga.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	solicitud := findElement(root, "s:Body/des:VerificaSolicitudDescarga/des:solicitud", internalNSMap)
	if solicitud == nil {
		t.Fatal("solicitud not found")
	}
	solicitud.CreateAttr("RfcSolicitante", testRFC)
	solicitud.CreateAttr("IdSolicitud", testIDSolicitud)

	parent := solicitud.Parent()
	parentBytes, err := canonicalize(parent)
	if err != nil {
		t.Fatal(err)
	}
	assertParity(t, "verifica_parent", parentBytes)
	assertParity(t, "verifica_signedinfo", signedInfoBytes(t, parentBytes))
}

func TestC14N_Descarga(t *testing.T) {
	doc, err := loadTemplate("descargamasiva.xml")
	if err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	solicitud := findElement(root,
		"s:Body/des:PeticionDescargaMasivaTercerosEntrada/des:peticionDescarga", internalNSMap)
	if solicitud == nil {
		t.Fatal("solicitud not found")
	}
	solicitud.CreateAttr("RfcSolicitante", testRFC)
	solicitud.CreateAttr("IdPaquete", testIDPaquete)

	parent := solicitud.Parent()
	parentBytes, err := canonicalize(parent)
	if err != nil {
		t.Fatal(err)
	}
	assertParity(t, "descarga_parent", parentBytes)
	assertParity(t, "descarga_signedinfo", signedInfoBytes(t, parentBytes))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(fmt.Errorf("setup: %w", err))
	}
}
