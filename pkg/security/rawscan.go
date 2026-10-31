package security

import (
	"bytes"
	"fmt"
	"io"
)

// rawVector define un token a localizar en los bytes crudos del archivo.
// El raw-scan es complementario al recorrido del árbol: lo intenta cuando
// el PDF es ilegible por parseo, o para confirmar tokens visibles en
// texto claro (fuera de object streams comprimidos).
type rawVector struct {
	token string
	code  string
	sev   Severity
	desc  string
}

// rawVectors tokens PDF case-sensitive según la especificación.
func rawVectors() []rawVector {
	return []rawVector{
		{"/JavaScript", VecJavaScript, SevHigh, "Token /JavaScript en bytes crudos"},
		{"/JS", VecJavaScript, SevHigh, "Token /JS en bytes crudos"},
		{"/OpenAction", VecOpenAction, SevMedium, "Token /OpenAction en bytes crudos"},
		{"/AA", VecAutoAction, SevMedium, "Token /AA en bytes crudos"},
		{"/Launch", VecLaunch, SevHigh, "Token /Launch en bytes crudos"},
		{"/EmbeddedFiles", VecEmbeddedFiles, SevMedium, "Token /EmbeddedFiles en bytes crudos"},
		{"/SubmitForm", VecSubmitForm, SevMedium, "Token /SubmitForm en bytes crudos"},
		{"/ImportData", VecImportData, SevMedium, "Token /ImportData en bytes crudos"},
		{"/RichMedia", VecRichMedia, SevMedium, "Token /RichMedia en bytes crudos"},
	}
}

// rawScan lee el archivo completo y cuenta cada token. Devuelve findings
// informativos (uno por token presente, agregado por ocurrencias).
func rawScan(rs io.ReadSeeker) []Finding {
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil
	}

	all, err := io.ReadAll(rs)
	if err != nil {
		return nil
	}

	var findings []Finding
	for _, rv := range rawVectors() {
		if n := bytes.Count(all, []byte(rv.token)); n > 0 {
			findings = append(findings, Finding{
				Code:        VecRawHint,
				Severity:    SevInfo,
				Description: fmt.Sprintf("%s (ocurrencias: %d)", rv.desc, n),
			})
		}
	}
	return findings
}

// mergeRawHints agrega hints crudos deduplicados y marca una nota.
func (a *Auditor) mergeRawHints(raw []Finding) {
	if len(raw) == 0 {
		return
	}
	existing := map[string]bool{}
	for _, f := range a.findings {
		if f.Code == VecRawHint {
			existing[f.Description] = true
		}
	}
	merged := 0
	for _, f := range raw {
		if existing[f.Description] {
			continue
		}
		existing[f.Description] = true
		a.findings = append(a.findings, f)
		merged++
	}
	if merged > 0 {
		a.notes = append(a.notes,
			"Los RAW_HINT son informativos: pueden duplicar hallazgos del árbol o ser texto inofensivo (p. ej. en metadatos)")
	}
}
