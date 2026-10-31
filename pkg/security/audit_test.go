package security

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// buildPDF construye un PDF mínimo válido con los objetos provistos
// (bodies son representaciones PDF raw, SIN el header/trailer) y calcula
// offsets y xref deterministamente, para poder inyectar vectores de
// seguridad realistas en fixtures de tests.
func buildPDF(t *testing.T, bodies []string) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")

	var rawObjs []string
	for _, b := range bodies {
		rawObjs = append(rawObjs, b)
	}

	offsets := make([]int, len(rawObjs)+1)
	for i, body := range rawObjs {
		offsets[i+1] = buf.Len()
		buf.WriteString(body)
	}

	xrefStart := buf.Len()
	total := len(rawObjs) + 1
	buf.WriteString(fmt.Sprintf("xref\n0 %d\n", total))
	buf.WriteString("0000000000 65535 f \n")
	for i := range rawObjs {
		buf.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[i+1]))
	}
	buf.WriteString("trailer\n<< /Size " + fmt.Sprint(total) + " /Root 1 0 R >>\n")
	buf.WriteString("startxref\n")
	buf.WriteString(fmt.Sprint(xrefStart))
	buf.WriteString("\n%%EOF\n")

	return buf.Bytes()
}

// --- Fixtures -------------------------------------------------------------

func pdfClean(t *testing.T) []byte {
	return buildPDF(t, []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
	})
}

func pdfWithJSAction(t *testing.T) []byte {
	return buildPDF(t, []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
		"4 0 obj\n<< /S /JavaScript /JS (app.launchURL\\(\\\"http://evil.x\\\"\\);) >>\nendobj\n",
	})
}

func pdfWithLaunch(t *testing.T) []byte {
	return buildPDF(t, []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
		"4 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n",
	})
}

func pdfWithEmbeddedFiles(t *testing.T) []byte {
	return buildPDF(t, []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles 4 0 R >> >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n",
		"4 0 obj\n<< /Names [ (payload.pdf) 5 0 R ] >>\nendobj\n",
		"5 0 obj\n<< /Type /Filespec /F (payload.pdf) /EF << /F 6 0 R >> >>\nendobj\n",
		"6 0 obj\n<< /Length 5 >>\nstream\nEVIL!\nendstream\nendobj\n",
	})
}

func pdfWithAutoActionAA(t *testing.T) []byte {
	return buildPDF(t, []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /AA << /X 4 0 R >> >>\nendobj\n",
		"4 0 obj\n<< /S /JavaScript /JS (alert\\(1\\);) >>\nendobj\n",
	})
}

// --- Tests ----------------------------------------------------------------

func TestAuditClean(t *testing.T) {
	rep, err := Audit("clean.pdf", bytes.NewReader(pdfClean(t)))
	if err != nil {
		t.Fatalf("Audit falló: %v", err)
	}
	if !rep.Clean {
		for _, f := range rep.Findings {
			t.Logf("hallazgo inesperado: %+v", f)
		}
		t.Fatalf("expected clean, got %d hallazgos", len(rep.Findings))
	}
	if rep.Scanned < 3 {
		t.Fatalf("escaneó %d objetos, esperaba al menos 3", rep.Scanned)
	}
}

func TestAuditDetectaJavaScriptEnOpenAction(t *testing.T) {
	rep, err := Audit("js.pdf", bytes.NewReader(pdfWithJSAction(t)))
	if err != nil {
		t.Fatalf("Audit falló: %v", err)
	}

	// Esperamos: OpenAction (media) en catálogo + JS action (alta).
	var gotJS, gotOpenAction bool
	for _, f := range rep.Findings {
		switch f.Code {
		case VecJavaScript:
			gotJS = true
		case VecOpenAction:
			gotOpenAction = true
		}
	}
	if !gotJS {
		t.Fatalf("no se detectó el JS embebido — hallazgos: %+v", rep.Findings)
	}
	if !gotOpenAction {
		t.Fatalf("no se detectó la acción de apertura — hallazgos: %+v", rep.Findings)
	}
	if rep.MaxSev != SevHigh {
		t.Fatalf("severidad máxima = %s, esperaba alta", rep.MaxSev)
	}
}

func TestAuditDetectaPayloadJS(t *testing.T) {
	rep, _ := Audit("js2.pdf", bytes.NewReader(pdfWithJSAction(t)))
	saw := false
	for _, f := range rep.Findings {
		if f.Code == VecJavaScript && f.Value != "" {
			saw = true
		}
	}
	if !saw {
		t.Fatal("el payload JavaScript no fue capturado en el reporte")
	}
}

func TestAuditDetectaLaunch(t *testing.T) {
	rep, err := Audit("launch.pdf", bytes.NewReader(pdfWithLaunch(t)))
	if err != nil {
		t.Fatalf("Audit falló: %v", err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Code == VecLaunch && f.Severity == SevHigh {
			found = true
		}
	}
	if !found {
		for _, f := range rep.Findings {
			t.Logf("%+v", f)
		}
		t.Fatal("no se detectó la acción /Launch")
	}
}

func TestAuditDetectaEmbeddedFiles(t *testing.T) {
	rep, err := Audit("attach.pdf", bytes.NewReader(pdfWithEmbeddedFiles(t)))
	if err != nil {
		t.Fatalf("Audit falló: %v", err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Code == VecEmbeddedFiles && f.Severity == SevMedium {
			found = true
		}
	}
	if !found {
		for _, f := range rep.Findings {
			t.Logf("%+v", f)
		}
		t.Fatal("no se detectó /EmbeddedFiles")
	}
}

func TestAuditDetectaAA(t *testing.T) {
	rep, err := Audit("aa.pdf", bytes.NewReader(pdfWithAutoActionAA(t)))
	if err != nil {
		t.Fatalf("Audit falló: %v", err)
	}
	var gotAA, gotJS bool
	for _, f := range rep.Findings {
		switch f.Code {
		case VecAutoAction:
			gotAA = true
		case VecJavaScript:
			gotJS = true
		}
	}
	if !gotAA || !gotJS {
		t.Fatalf("falta AA=%v JS=%v — hallazgos: %+v", gotAA, gotJS, rep.Findings)
	}
}

func TestAuditRawScanFallbackEnIlegible(t *testing.T) {
	// bytes con vectores pero sin estructura PDF parseable.
	junk := []byte("%%PDF-1.7 esto no es un pdf válido /JavaScript /Launch /OpenAction")
	rep, err := Audit("junk.pdf", bytes.NewReader(junk))
	if err != nil {
		t.Fatalf("Audit no debería fallar duro con fallback: %v", err)
	}
	if rep.Notes == nil {
		t.Fatal("esperaba nota de auditoría parcial")
	}
	// al menos el raw hint de /JavaScript debería aparecer.
	ok := false
	for _, f := range rep.Findings {
		if f.Code == VecRawHint && f.Description != "" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("el fallback raw-scan no produjo hints")
	}
}

func TestReportJSONSerializa(t *testing.T) {
	rep, _ := Audit("aa.pdf", bytes.NewReader(pdfWithAutoActionAA(t)))
	data, err := ReportJSON(rep)
	if err != nil {
		t.Fatalf("serialización JSON: %v", err)
	}
	if !bytes.Contains(data, []byte(`"JS_EMBEDDED"`)) {
		t.Fatalf("JSON sin código de vector: %s", string(data))
	}
}

// Verifica el flujo end-to-end con archivo en disco (estabilidad del lector Seek).
func TestAuditConArchivoEnDisco(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aa.pdf")
	if err := os.WriteFile(path, pdfWithAutoActionAA(t), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rep, err := Audit(path, f)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean {
		t.Fatal("limpio en fixture con AA/JS")
	}
}
