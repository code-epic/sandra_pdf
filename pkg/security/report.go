package security

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ---------------------------------------------------------------------------
// Formatos de salida del reporte de auditoría
// ---------------------------------------------------------------------------

// ReportJSON serializa el reporte a JSON estándar.
func ReportJSON(r *Report) ([]byte, error) {
	// BySeverity es mapa de detalles para humanos: se excluye del JSON
	// para mantener el resultado tipificado y estable entre versiones.
	r.BySeverity = nil
	return json.MarshalIndent(r, "", "  ")
}

// PrintReport escribe el reporte legible por humanos a w.
func PrintReport(w io.Writer, r *Report) {
	fmt.Fprintln(w, "===============================================")
	fmt.Fprintln(w, " AUDITORÍA DE SEGURIDAD PDF — sandra_pdf")
	fmt.Fprintln(w, "===============================================")
	fmt.Fprintf(w, " Archivo:            %s\n", r.FileName)
	fmt.Fprintf(w, " Objetos escaneados: %d\n", r.Scanned)

	if len(r.Notes) > 0 {
		for _, n := range r.Notes {
			fmt.Fprintf(w, " Nota:       %s\n", n)
		}
	}

	if r.Clean {
		fmt.Fprintln(w, " RESULTADO: LIMPIO — no se detectaron vectores de riesgo conocidos.")
		fmt.Fprintln(w, "===============================================")
		return
	}

	fmt.Fprintln(w, "-----------------------------------------------")
	fmt.Fprintf(w, " ALERTAS: %d total\n", len(r.Findings))

	orden := []Severity{SevCritical, SevHigh, SevMedium, SevInfo}
	porSev := map[Severity]int{}
	for _, f := range r.Findings {
		porSev[f.Severity]++
	}
	for _, s := range orden {
		if porSev[s] > 0 {
			fmt.Fprintf(w, "   severidad %-8s: %d\n", s, porSev[s])
		}
	}

	fmt.Fprintln(w, "-----------------------------------------------")
	for i, f := range r.Findings {
		if i > 0 {
			fmt.Fprint(w, " \n")
		}
		objInfo := ""
		if f.ObjNr > 0 {
			objInfo = fmt.Sprintf(" obj#%d", f.ObjNr)
		}
		fmt.Fprintf(w, " [%d] %s* (%s)%s\n", i+1, strings.ToUpper(string(f.Severity)), severityIcon(f.Severity), objInfo)
		fmt.Fprintf(w, "     código: %s\n", f.Code)
		fmt.Fprintf(w, "     %s\n", f.Description)
		if f.Value != "" {
			fmt.Fprintf(w, "     payload: %q\n", f.Value)
		}
	}
	fmt.Fprintln(w, "===============================================")
	fmt.Fprintf(w, " RESULTADO: %d alerta(s) — severidad máxima: %s %s\n",
		len(r.Findings), r.MaxSev, severityIcon(r.MaxSev))
}

// severityIcon íconos simples para terminal.
func severityIcon(s Severity) string {
	switch s {
	case SevCritical:
		return "[!!]"
	case SevHigh:
		return "[!]"
	case SevMedium:
		return "[~]"
	case SevInfo:
		return "[i]"
	}
	return ""
}
