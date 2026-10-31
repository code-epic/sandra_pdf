// Package security implementa el inspector de seguridad del PDF:
// detección de JavaScript embebido, acciones automáticas, ejecución
// externa y archivos incrustados, a partir del árbol de objetos.
package security

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// Severity de una alerta de seguridad.
type Severity string

// Niveles de severidad (mayor = más grave).
const (
	SevInfo     Severity = "info"
	SevMedium   Severity = "media"
	SevHigh     Severity = "alta"
	SevCritical Severity = "critica"
)

// Códigos de vector reportados por el auditor.
const (
	VecJavaScript    = "JS_EMBEDDED"    // JavaScript embebido (/JavaScript, /JS)
	VecOpenAction    = "OPEN_ACTION"    // /OpenAction en el catálogo
	VecAutoAction    = "AUTO_ACTION"    // /AA en páginas o anotaciones
	VecLaunch        = "LAUNCH"         // ejecución externa (/Launch)
	VecEmbeddedFiles = "EMBEDDED_FILES" // archivos incrustados
	VecSubmitForm    = "SUBMIT_FORM"    // envío de datos a URL (POST)
	VecImportData    = "IMPORT_DATA"    // importación de FDF externo
	VecExternalURL   = "EXTERNAL_URL"   // hipervínculos a recursos externos
	VecRichMedia     = "RICH_MEDIA"     // contenido rico ejecutable
	VecRawHint       = "RAW_HINT"       // token en bytes crudos (posible falso positivo)
)

// maxDepth limita la recursión para prevenir bucles maliciosos.
const maxDepth = 48

// maxSnippet máx caracteres del payload reportado.
const maxSnippet = 160

// Finding es una alerta concreta emitida por el auditor.
type Finding struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	ObjNr       int      `json:"objNr"`
	Value       string   `json:"valor,omitempty"`
}

// Report del escaneo de seguridad.
type Report struct {
	FileName   string           `json:"archivo"`
	Findings   []Finding        `json:"alertas"`
	Scanned    int              `json:"objetosEscaneados"`
	Notes      []string         `json:"notas,omitempty"`
	Clean      bool             `json:"limpio"`
	MaxSev     Severity         `json:"severidadMaxima,omitempty"`
	BySeverity map[Severity]int `json:"sevDetalle,omitempty"`
}

// Auditor es el inspector estructurado del árbol de objetos.
type Auditor struct {
	visited  map[string]bool // dedup code+objNr
	findings []Finding
	maxSev   Severity
	scanned  int
	notes    []string
}

// NewAuditor construye un auditor con estado limpio.
func NewAuditor() *Auditor {
	return &Auditor{visited: map[string]bool{}}
}

// Audit escanea el PDF completo y produce un Report.
// Combina el árbol completo vía pdfcpu (incluyendo object streams) con un
// escaneo crudo de bytes para vectores en texto claro.
func Audit(fileName string, rs io.ReadSeeker) (*Report, error) {
	a := NewAuditor()

	c := auditConf()
	c.DecodeAllStreams = true // materializar objetos dentro de object streams

	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	ctx, err := api.ReadContext(rs, c)
	if err != nil {
		return a.partialScan(rs, fileName, err), nil
	}

	// Recorrido del árbol de objetos.
	for objNr, entry := range ctx.Table {
		if entry == nil || entry.Free {
			continue
		}
		a.scanned++
		a.inspect(ctx, objNr, entry.Object, "", 0)
	}

	// Escaneo expreso del árbol de nombres del catálogo (name trees).
	if namesObj, ok := ctx.RootDict.Find("Names"); ok {
		a.scanned++
		a.inspect(ctx, 0, namesObj, "/Names", 0)
	}

	// Escaneo crudo complementario de bytes.
	if _, err := rs.Seek(0, io.SeekStart); err == nil {
		if rawHits := rawScan(rs); len(rawHits) > 0 {
			a.mergeRawHints(rawHits)
		}
	}

	return a.report(fileName), nil
}

// auditConf configuración de lectura tolerante.
func auditConf() *model.Configuration {
	api.DisableConfigDir()
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	return conf
}

// partialScan se usa cuando pdfcpu no puede parsear: falla a byte-scan.
func (a *Auditor) partialScan(rs io.ReadSeeker, fileName string, parseErr error) *Report {
	a.notes = append(a.notes, fmt.Sprintf(
		"parser pdfcpu no logró leer el PDF (%v): auditoría parcial vía byte-scan", parseErr))
	if hits := rawScan(rs); len(hits) > 0 {
		a.mergeRawHints(hits)
	}
	return a.report(fileName)
}

// ----------------------------------------------------------------------------
// Inspección recursiva
// ----------------------------------------------------------------------------

func (a *Auditor) inspect(ctx *model.Context, objNr int, o types.Object, path string, depth int) {
	switch d := o.(type) {
	case types.Dict:
		a.inspectDict(ctx, objNr, d, path, depth)
	case *types.StreamDict:
		// el dict del stream puede contener acciones JS u OpenAction.
		a.inspectDict(ctx, objNr, d.Dict, path+"/stream", depth)
	case types.Array:
		for _, it := range d {
			a.inspect(ctx, objNr, it, path, depth)
		}
	case *types.LazyObjectStreamObject:
		obj, err := d.DecodedObject(context.Background())
		if err == nil {
			a.inspect(ctx, objNr, obj, path, depth)
		}
	}
}

// suspectKey describe una llave sospechosa de nivel documental.
type suspectKey struct {
	key  string
	sev  Severity
	code string
	desc string
}

// suspectKeys lista de llaves a detectar por nombre directo.
func suspectKeys() []suspectKey {
	return []suspectKey{
		{"JavaScript", SevHigh, VecJavaScript, "Clave /JavaScript presente (name tree o dict de JS embebido)"},
		{"JS", SevHigh, VecJavaScript, "Clave /JS presente (payload JavaScript)"},
		{"OpenAction", SevMedium, VecOpenAction, "Acción de apertura automática (/OpenAction) - se ejecuta al abrir"},
		{"AA", SevMedium, VecAutoAction, "Acciones adicionales automáticas (/AA) - se ejecutan en eventos"},
		{"EmbeddedFiles", SevMedium, VecEmbeddedFiles, "Archivos adicionales incrustados (/EmbeddedFiles)"},
		{"RichMediaExecute", SevHigh, VecRichMedia, "Ejecución de contenido enriquecido (/RichMediaExecute)"},
		{"RichMediaData", SevMedium, VecRichMedia, "Payload de contenido enriquecido (/RichMediaData, típicamente SWF)"},
		{"SilentPrint", SevHigh, VecAutoAction, "Impresión silenciosa (/SilentPrint)"},
		{"SubmitForm", SevMedium, VecSubmitForm, "Envío de formulario externo (/SubmitForm)"},
		{"ImportData", SevMedium, VecImportData, "Importación de datos FDF (/ImportData)"},
	}
}

// inspectDict revisa llaves sospechosas y recursiona en los valores.
func (a *Auditor) inspectDict(ctx *model.Context, objNr int, d types.Dict, path string, depth int) {
	if depth > maxDepth {
		return
	}

	// Acción expresa: la llave /S define el tipo de acción.
	a.inspectAction(ctx, objNr, d)

	// Llaves por nombre.
	for _, sk := range suspectKeys() {
		if _, ok := d.Find(sk.key); ok {
			val := ""
			if sk.code == VecJavaScript {
				val = a.derefStr(ctx, d["JS"])
			}
			a.add(Finding{
				Code:        sk.code,
				Severity:    sk.sev,
				Description: sk.desc,
				ObjNr:       objNr,
				Value:       snippet(val),
			})
		}
	}

	// Recursión en valores (arrays internos incluidos). Dict es un map:
	// se itera directamente por clave (el orden no es relevante aquí).
	for k, v := range d {
		a.inspect(ctx, objNr, v, path+"/"+k, depth+1)
	}
}

// inspectAction revisa la llave /S de una acción.
func (a *Auditor) inspectAction(ctx *model.Context, objNr int, d types.Dict) {
	sn, ok := d.Find("S")
	if !ok {
		return
	}
	name, ok := sn.(types.Name)
	if !ok {
		return
	}

	switch string(name) {
	case "JavaScript":
		a.add(Finding{
			Code:        VecJavaScript,
			Severity:    SevHigh,
			Description: "Acción JavaScript embebida (/S /JavaScript)",
			ObjNr:       objNr,
			Value:       snippet(a.derefStr(ctx, d["JS"])),
		})
	case "Launch":
		a.add(Finding{
			Code:        VecLaunch,
			Severity:    SevHigh,
			Description: "Acción de ejecución externa (/S /Launch) - invoca comandos del sistema",
			ObjNr:       objNr,
			Value:       snippet(a.derefStr(ctx, d["F"])),
		})
	case "SubmitForm":
		a.add(Finding{
			Code:        VecSubmitForm,
			Severity:    SevMedium,
			Description: "Envío de formulario a recurso externo (/S /SubmitForm)",
			ObjNr:       objNr,
		})
	case "ImportData":
		a.add(Finding{
			Code:        VecImportData,
			Severity:    SevMedium,
			Description: "Importación de datos FDF externo (/S /ImportData)",
			ObjNr:       objNr,
		})
	case "Rendition", "Movie":
		a.add(Finding{
			Code:        VecRichMedia,
			Severity:    SevMedium,
			Description: "Contenido rico (Rendition/Movie) en el documento",
			ObjNr:       objNr,
		})
	case "GoToR":
		a.add(Finding{
			Code:        VecExternalURL,
			Severity:    SevInfo,
			Description: "Navegación remota hacia otro documento (/S /GoToR)",
			ObjNr:       objNr,
		})
	}
}

// derefStr intenta resolver un string (literal o hex) de un objeto.
func (a *Auditor) derefStr(ctx *model.Context, o types.Object) string {
	if o == nil {
		return ""
	}
	s, err := ctx.DereferenceStringOrHexLiteral(o, model.V10, nil)
	if err != nil || s == "" {
		// Puede ser referencia a un FileSpec dict (/F): intenta extraer UF/F.
		if ir, ok := o.(types.IndirectRef); ok {
			if d, err := ctx.DereferenceDict(ir); err == nil && d != nil {
				if fs, ok := d.Find("UF"); ok {
					return a.derefStr(ctx, fs)
				}
				if fs, ok := d.Find("F"); ok {
					return a.derefStr(ctx, fs)
				}
			}
		}
		return ""
	}
	return s
}

// ----------------------------------------------------------------------------
// Consolidación
// ----------------------------------------------------------------------------

// add registra un hallazgo con dedup por código+objeto.
func (a *Auditor) add(f Finding) {
	key := fmt.Sprintf("%s#%d", f.Code, f.ObjNr)
	if a.visited[key] {
		return
	}
	a.visited[key] = true
	a.findings = append(a.findings, f)
	if sevRank(f.Severity) > sevRank(a.maxSev) {
		a.maxSev = f.Severity
	}
}

// report consolida el resultado final.
func (a *Auditor) report(fileName string) *Report {
	sevCounts := map[Severity]int{}
	for _, f := range a.findings {
		sevCounts[f.Severity]++
	}
	return &Report{
		FileName:   fileName,
		Findings:   a.findings,
		Scanned:    a.scanned,
		Notes:      a.notes,
		Clean:      len(a.findings) == 0,
		MaxSev:     a.maxSev,
		BySeverity: sevCounts,
	}
}

// sevRank para comparar severidades.
func sevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// snippet trunca el payload para el reporte.
func snippet(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", "\\n"))
	runes := []rune(s)
	if len(runes) > maxSnippet {
		return string(runes[:maxSnippet]) + "...(truncado)"
	}
	return s
}
