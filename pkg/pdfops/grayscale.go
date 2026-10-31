package pdfops

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"strconv"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// ============================================================================
// Conversión de páginas a escala de grises (DeviceGray).
//
// Dos pasadas sobre el árbol de objetos:
//
//  1. Content streams (páginas + XObjects /Form): reescritura de operadores
//     de color de la especificación PDF (Tablas 74-75 "Colour operators"):
//       rg → g   DeviceRGB no-stroking      RG → G   DeviceRGB stroking
//       k  → g   DeviceCMYK no-stroking     K  → G   DeviceCMYK stroking
//       sc/scn/SC/SCN con operandos numéricos → g/G según contexto
//     El scanner respeta la sintaxis: literales (…), hex strings <…>,
//     diccionarios <<…>> e imágenes inline BI/ID/EI se preservan verbatim.
//
//  2. Imágenes (XObject /Image): conversión de muestras
//       - FlateDecode RGB/CMYK 8bpc → luminancia Y = .299/.587/.114
//       - DCTDecode (JPEG)         → decodifica stdlib, gris, re-encoding
//     ICCBased N>=2, Separation, DeviceN, JPX y CCITT se omiten con
//     advertencia (pdfcpu los copia tal cual).
// ============================================================================

// GrayResult resume la conversión para el feedback del CLI.
type GrayResult struct {
	PagesProcessed   int      // páginas pasadas
	StreamsRewritten int      // content streams con operadores reescritos
	ImagesConverted  int      // imágenes RGB/CMYK convertidas a DeviceGray
	ImagesSkipped    []string // imágenes no convertibles, con motivo
	Warnings         []string
}

// rgbToGray calcula la luminancia para coordenadas r/g/b en [0,1]
// según los coeficientes estándar ITU-R BT.601.
func rgbToGray(r, g, b float64) float64 {
	return clamp01(0.299*r + 0.587*g + 0.114*b)
}

// cmykToGray aproxima DeviceCMYK → gris (blanco = 0).
func cmykToGray(c, m, y, k float64) float64 {
	// Y = (1 - K) * (1 - min(1, 0.35C + 0.45M + 0.2Y))
	t := 0.35*c + 0.45*m + 0.2*y
	return clamp01((1 - k) * (1 - clamp01(t)))
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

// Grayscale convierte todas las páginas del PDF a DeviceGray escribiendo el
// resultado en w. Devuelve estadísticas para el feedback del CLI.
func Grayscale(rs io.ReadSeeker, w io.Writer) (*GrayResult, error) {
	c := confRelaxed()
	c.DecodeAllStreams = true // materializar objetos dentro de object streams

	ctx, err := api.ReadContext(rs, c)
	if err != nil {
		return nil, fmt.Errorf("grayscale: lectura del PDF: %w", err)
	}

	res := &GrayResult{}
	xRefTable := ctx.XRefTable

	// ReadContext no valida; PageCount queda en 0. Falta materializarlo
	// desde el /Count del page tree (api.ReadContext no lo hace).
	if err := xRefTable.EnsurePageCount(); err != nil {
		return nil, fmt.Errorf("grayscale: conteo de páginas: %w", err)
	}

	// --- Pasada 1: content streams de páginas + form XObjects. ---
	for p := 1; p <= xRefTable.PageCount; p++ {
		res.PagesProcessed++
		pageDict, _, _, err := xRefTable.PageDict(p, false)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("página %d: %v", p, err))
			continue
		}

		nStreams, err := grayscaleContents(ctx, pageDict)
		res.StreamsRewritten += nStreams
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("página %d: %v", p, err))
		}
	}

	// --- Pasada 2: imágenes RGB/CMYK del árbol de objetos. ---
	if err := grayscaleImages(ctx, res); err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	}

	// --- Escritura final ---------------------------------------------------
	// Escribir el ctx crudo (api.Write sin validación) genera XRef inválida y
	// fuentes con glifos rotos en el PDF resultante. Sanitizar con el mismo
	// pipeline de ops.Optimize (EnsurePageCount + Validate + Optimize) antes
	// de escribir, en memoria.
	if err := xRefTable.EnsurePageCount(); err != nil {
		return res, fmt.Errorf("grayscale: conteo de páginas: %w", err)
	}
	if err := api.ValidateContext(ctx); err != nil {
		return res, fmt.Errorf("grayscale: validación: %w", err)
	}
	if err := api.OptimizeContext(ctx); err != nil {
		return res, fmt.Errorf("grayscale: optimización: %w", err)
	}
	if err := api.WriteContext(ctx, w); err != nil {
		return res, fmt.Errorf("grayscale: escritura: %w", err)
	}

	if len(res.Warnings) == 0 {
		res.Warnings = nil
	}
	return res, nil
}

// ----------------------------------------------------------------------------
// Pasada 1: content streams
// ----------------------------------------------------------------------------

// grayscaleContents reescribe los operadores de color del /Contents de la
// página y de los XObjects /Form en su /Resources. Devuelve streams modificados.
//
// IMPORTANTE: pdfcpu's DereferenceStreamDict devuelve un puntero a una COPIA
// del StreamDict del entry (line 1004-1009 de xreftable.go). Para que las
// mutaciones persistan al escribir, hay que reasignar entry.Object con el
// dict modificado (persistStreamDict).
func grayscaleContents(ctx *model.Context, pageDict types.Dict) (int, error) {
	rewritten := 0

	// 1) /Contents de la página: referencia simple o array de streams.
	switch o := pageDict["Contents"].(type) {
	case types.IndirectRef:
		sd, _, err := ctx.DereferenceStreamDict(o)
		if err != nil || sd == nil {
			return rewritten, err
		}
		n, err := rewriteContentStream(sd)
		if err != nil {
			return rewritten, err
		}
		if n > 0 {
			persistStreamDict(ctx, o, sd)
		}
		rewritten += n

	case types.Array:
		for _, it := range o {
			ir, ok := it.(types.IndirectRef)
			if !ok {
				continue
			}
			sd, _, err := ctx.DereferenceStreamDict(ir)
			if err != nil || sd == nil {
				continue
			}
			n, err := rewriteContentStream(sd)
			if err != nil {
				continue
			}
			if n > 0 {
				persistStreamDict(ctx, ir, sd)
			}
			rewritten += n
		}
	}

	// 2) /Resources → /XObject → /Form de la página.
	resObj, ok := pageDict.Find("Resources")
	if !ok {
		return rewritten, nil
	}
	resDict, err := ctx.DereferenceDict(resObj)
	if err != nil || resDict == nil {
		return rewritten, nil
	}

	xaObj, ok := resDict.Find("XObject")
	if !ok {
		return rewritten, nil
	}
	xoDict, err := ctx.DereferenceDict(xaObj)
	if err != nil || xoDict == nil {
		return rewritten, nil
	}

	// Dict es un map: iteramos claves directamente.
	for key := range xoDict {
		obj, ok := xoDict[key]
		if !ok {
			continue
		}
		ir, ok := obj.(types.IndirectRef)
		if !ok {
			continue
		}
		sd, err := ctx.DereferenceXObjectDict(ir)
		if err != nil || sd == nil {
			continue
		}
		if sub := sd.Subtype(); sub == nil || *sub != "Form" {
			continue // las imágenes van por la pasada 2
		}
		n, err := rewriteContentStream(sd)
		if err != nil {
			continue
		}
		if n > 0 {
			persistStreamDict(ctx, ir, sd)
		}
		rewritten += n
	}
	return rewritten, nil
}

// persistStreamDict reasigna el StreamDict mutado en su entrada del
// XRefTable, para que pdfcpu lo escriba en el output.
func persistStreamDict(ctx *model.Context, ir types.IndirectRef, sd *types.StreamDict) {
	entry, found := ctx.XRefTable.FindTableEntry(
		ir.ObjectNumber.Value(), ir.GenerationNumber.Value())
	if found && entry != nil {
		entry.Object = *sd
	}
}

// rewriteContentStream decodifica el stream, aplica el scanner de color y
// re-encodifica si hubo cambios. Devuelve 1 si el stream fue modificado.
func rewriteContentStream(sd *types.StreamDict) (int, error) {
	if err := sd.Decode(); err != nil {
		return 0, err
	}
	if len(sd.Content) == 0 {
		return 0, nil
	}

	newBytes, changed := grayTransformContent(sd.Content)
	if !changed {
		return 0, nil // stream ya monocromo; no tocarlo
	}

	sd.Content = newBytes
	if err := sd.Encode(); err != nil {
		return 0, fmt.Errorf("encode content stream: %w", err)
	}
	return 1, nil
}

// ----------------------------------------------------------------------------
// Transformador de operadores de color
// ----------------------------------------------------------------------------

// isNumericToken: operando numérico decimal (int, real, negativos).
func isNumericToken(s string) bool {
	if s == "" {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// grayTransformContent convierte los operadores de color a DeviceGray.
//
// Estado: los operandos numéricos consecutivos se acumulan en `pending` SIN
// escribirse; se resuelven cuando llega su operador de color (rg/RG/k/K/sc…)
// o bien se "tabulan" verbatim ante cualquier otro token. Esto garantiza
// que los operandos que convierte un operador NUNCA se dupliquen y que el
// valor convertido siempre queda separado del operador ("0.5000 g").
func grayTransformContent(content []byte) ([]byte, bool) {
	ts := newTokenStream(content)
	out := &bytes.Buffer{}
	changed := false
	var pending []string // operandos numéricos consecutivos (provisionales)

	// flushPending escribe los operandos acumulados verbatim y los descarta.
	flushPending := func() {
		for _, p := range pending {
			out.WriteString(p)
			out.WriteByte(' ')
		}
		pending = nil
	}

	// emitGray escribe el valor convertido + operador y descarta los
	// operandos pendientes que acaba de consumir.
	emitGray := func(grayOp string, v float64, converted bool) {
		if converted {
			changed = true
		}
		out.WriteString(fmtGray(v) + " " + grayOp + " ")
		pending = nil
	}

	for {
		tok, ok := ts.next()
		if !ok {
			break
		}

		if isNumericToken(tok) {
			pending = append(pending, tok)
			continue
		}

		// Token no numérico: primero se descarga lo pendiente.
		switch tok {
		case "rg", "RG":
			ops := lastN(pending, 3)
			if isAllNumeric(ops) && len(pending) == 3 {
				g := rgbToGray(pf(ops[0]), pf(ops[1]), pf(ops[2]))
				grayOp := "g" // rg es non-stroking
				if tok == "RG" {
					grayOp = "G"
				}
				emitGray(grayOp, g, true)
			} else {
				flushPending()
				out.WriteString(tok + " ")
			}

		case "k", "K":
			ops := lastN(pending, 4)
			if isAllNumeric(ops) && len(pending) == 4 {
				g := cmykToGray(pf(ops[0]), pf(ops[1]), pf(ops[2]), pf(ops[3]))
				grayOp := "g"
				if tok == "K" {
					grayOp = "G"
				}
				emitGray(grayOp, g, true)
			} else {
				flushPending()
				out.WriteString(tok + " ")
			}

		case "g", "G":
			// DeviceGray de por sí: operandos + operador verbatim.
			flushPending()
			out.WriteString(tok + " ")

		case "sc", "SC", "scn", "SCN":
			switch {
			case isAllNumeric(pending) && len(pending) == 1:
				// Un solo operando: DeviceGray nativo, passthrough.
				flushPending()
				out.WriteString(tok + " ")
			case isAllNumeric(pending) && len(pending) == 3:
				g := rgbToGray(pf(pending[0]), pf(pending[1]), pf(pending[2]))
				emitGray(grayOpFor(tok), g, true)
			case isAllNumeric(pending) && len(pending) == 4:
				g := cmykToGray(pf(pending[0]), pf(pending[1]), pf(pending[2]), pf(pending[3]))
				emitGray(grayOpFor(tok), g, true)
			default:
				// /Name o array de operandos: patterns o tintes de espacios
				// no convertibles → verbatim.
				flushPending()
				out.WriteString(tok + " ")
			}

		default:
			// Cualquier otro token (strings, dicts, /Names, arrays, cs/CS/ri,
			// q Q BT ET cm Do Tm TJ…) tabula operandos y token verbatim.
			flushPending()
			out.WriteString(tok + " ")
		}
	}
	// Operandos huérfanos al final del stream (malformado): verbatim.
	flushPending()

	if !changed {
		return content, false
	}
	return out.Bytes(), true
}

func grayOpFor(tok string) string {
	switch tok {
	case "SC", "SCN":
		return "G"
	default:
		return "g"
	}
}

func isColorOp(op string) bool {
	switch op {
	case "rg", "RG", "g", "G", "k", "K",
		"sc", "SC", "scn", "SCN",
		"cs", "CS", "ri":
		return true
	}
	return false
}

func isAllNumeric(s []string) bool {
	if len(s) == 0 {
		return false
	}
	for _, x := range s {
		if !isNumericToken(x) {
			return false
		}
	}
	return true
}

func lastN(s []string, n int) []string {
	if len(s) < n {
		return nil
	}
	return s[len(s)-n:]
}

func pf(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

func fmtGray(v float64) string {
	return strconv.FormatFloat(v, 'f', 4, 64)
}

// ----------------------------------------------------------------------------
// Tokenizer de content streams
// ----------------------------------------------------------------------------

// tokenStream troza un content stream decodificado. Respeta:
//   - literales (…) con anidamiento y escapes \(\)\\
//   - hex strings <…> y dicts <<…>>
//   - arrays [ ] como tokens separados para no mezclar operandos
//   - imágenes inline BI … ID … EI (se arraman al cierre del data binario)
//   - comentarios % … EOL
type tokenStream struct {
	src []byte
	pos int
}

func newTokenStream(src []byte) *tokenStream {
	return &tokenStream{src: src}
}

func (ts *tokenStream) skipWhitespace() {
	for ts.pos < len(ts.src) {
		c := ts.src[ts.pos]
		switch c {
		case ' ', '\t', '\r', '\n', '\f', '\x00':
			ts.pos++
		case '%':
			for ts.pos < len(ts.src) && ts.src[ts.pos] != '\n' {
				ts.pos++
			}
		default:
			return
		}
	}
}

// next() devuelve el siguiente token (EOF → false, "", "ok").
// Includes: excepto literal/dict/hex que se decoran con sus delimitadores
// (se devuelven verbatim para preservar el contenido).
func (ts *tokenStream) next() (string, bool) {
	ts.skipWhitespace()
	if ts.pos >= len(ts.src) {
		return "", false
	}
	src := ts.src
	n := len(src)
	start := ts.pos
	c := src[ts.pos]

	switch c {
	case '(':
		// literal string con anidado ( nesting-aware ).
		depth := 1
		ts.pos++
		for ts.pos < n && depth > 0 {
			switch src[ts.pos] {
			case '\\':
				if ts.pos+1 < n {
					ts.pos += 2
				} else {
					ts.pos++
				}
				continue
			case '(':
				depth++
			case ')':
				depth--
			}
			ts.pos++
		}
		if ts.pos >= n {
			ts.pos = n
		}
		return string(src[start:ts.pos]), true

	case '<':
		if ts.pos+1 < n && src[ts.pos+1] == '<' {
			// dict: << ... >> (con anidado).
			depth := 1
			ts.pos += 2
			for ts.pos+1 <= n && depth > 0 && ts.pos < n {
				if ts.pos+1 < n && (ts.pos < n) {
					if src[ts.pos] == '<' && src[ts.pos+1] == '<' {
						depth++
						ts.pos += 2
						continue
					}
					if src[ts.pos] == '>' && src[ts.pos+1] == '>' {
						depth--
						ts.pos += 2
						continue
					}
				}
				ts.pos++
			}
			if ts.pos > n {
				ts.pos = n
			}
			return string(src[start:ts.pos]), true
		}
		// hex string <...>: hasta '>' inclusivo.
		for ts.pos < n && src[ts.pos] != '>' {
			ts.pos++
		}
		if ts.pos < n {
			ts.pos++
		}
		return string(src[start:ts.pos]), true

	case '[':
		ts.pos++
		return "[", true
	case ']':
		ts.pos++
		return "]", true

	case '/':
		// /Name: hasta separador.
		ts.pos++
		for ts.pos < n && !isWS(src[ts.pos]) && !isDelim(src[ts.pos]) {
			ts.pos++
		}
		return string(src[start:ts.pos]), true

	case 'B', 'I':
		// ¿imagen inline "BI"? seguido de espacio/ancho — apoyo para
		// saltar el bloque binario completo hasta el delimitador "EI".
		if c == 'B' && ts.pos+1 < n && src[ts.pos+1] == 'I' && ts.pos+2 < n && isWS(src[ts.pos+2]) {
			// BI + dict anónimo + ID + binario + EI.
			ts.pos += 2
			foundID := false
			for ts.pos < n {
				if src[ts.pos] == 'I' && ts.pos+1 < n && src[ts.pos+1] == 'D' {
					foundID = true
					ts.pos += 2
					break
				}
				ts.pos++
			}
			if foundID {
				// Buscar terminador "EI" no precedido por '\'
				end := searchInlineImageEnd(ts.src, ts.pos)
				if end > ts.pos {
					ts.pos = end
					return "EI", true
				}
				// Sin "EI" hallado: dejar el resto del stream inmune.
				ts.pos = n
				return "", true
			}
		}
		fallthrough

	default:
		// Números, operadores, otros tokens hasta separador.
		for ts.pos < n && !isWS(src[ts.pos]) && !isDelim(src[ts.pos]) {
			ts.pos++
		}
		if ts.pos == start {
			ts.pos++ // byte raro suelto; avanza para evitar bucle infinito
			return string(src[start:ts.pos]), true
		}
		return string(src[start:ts.pos]), true
	}
}

func isWS(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '\f', '\x00':
		return true
	}
	return false
}

func isDelim(c byte) bool {
	switch c {
	case '(', '[', '<', ']', ')', '/':
		return true
	}
	return false
}

// searchInlineImageEnd busca un token "EI" (Excepción: en el binario de
// inline images puede haber "EI". La pcráctica estándar es buscar el
// separador de estados seguido de un espacio/sep de bytes. La forma canónica
// es el byte de EOL (0x0A/0x0D) delante de "EI").
func searchInlineImageEnd(data []byte, from int) int {
	for i := from; i+2 <= len(data); i++ {
		if data[i] == 'E' && data[i+1] == 'I' {
			// Ei se acepta cuando está separado o al inicio de línea.
			sepOK := (i == from) || isWS(data[i-1])
			if sepOK {
				if i+2 >= len(data) || isWS(data[i+2]) {
					return i + 2
				}
			}
		}
	}
	return -1
}

// ----------------------------------------------------------------------------
// Pasada 2: imágenes
// ----------------------------------------------------------------------------

// grayscaleImages convierte XObjects /Image con DeviceRGB/DeviceCMYK
// (o ICC con N 3/4) a DeviceGray.
func grayscaleImages(ctx *model.Context, res *GrayResult) error {
	xRefTable := ctx.XRefTable

	for objNr := 1; objNr <= xRefTable.MaxObjNr; objNr++ {
		entry, found := xRefTable.Table[objNr]
		if !found || entry == nil || entry.Free {
			continue
		}

		// Los entries guardan StreamDict por valor (pdfcpu no usa puntero
		// aquí); aceptar ambas variantes por robustez entre versiones de
		// pdfcpu. OJO: convertir sobre una COPIA no persiste nada al
		// escribir; por eso tras la conversión reasentamos entry.Object.
		var sd types.StreamDict
		switch o := entry.Object.(type) {
		case types.StreamDict:
			sd = o
		case *types.StreamDict:
			sd = *o
		default:
			continue
		}
		if !sd.Image() {
			continue
		}

		bpcV := sd.IntEntry("BitsPerComponent")
		bpc := 8
		if bpcV != nil {
			bpc = *bpcV
		}
		if bpc != 8 {
			res.ImagesSkipped = append(res.ImagesSkipped, fmt.Sprintf(
				"obj %d: BitsPerComponent=%d no soportado", objNr, bpc))
			continue
		}

		wV := sd.IntEntry("Width")
		hV := sd.IntEntry("Height")
		if wV == nil || hV == nil || *wV <= 0 || *hV <= 0 {
			res.ImagesSkipped = append(res.ImagesSkipped,
				fmt.Sprintf("obj %d: dimensiones inválidas", objNr))
			continue
		}

		csName, comps, err := resolveColorSpace(ctx, &sd)
		if err != nil {
			res.ImagesSkipped = append(res.ImagesSkipped, fmt.Sprintf("obj %d: %v", objNr, err))
			continue
		}

		switch csName {
		case "DeviceGray", "CalGray", "G":
			// Ya es blanco y negro.
		case "DeviceRGB", "CalRGB", "RGB", "ICCRGB":
			if err := convertImageSamples(ctx, &sd, objNr, comps, res, true); err != nil {
				res.ImagesSkipped = append(res.ImagesSkipped, fmt.Sprintf(
					"obj %d (RGB): %v", objNr, err))
			} else {
				// persistir la conversión en el árbol de objetos
				entry.Object = sd
			}
		case "DeviceCMYK", "CMYK", "ICCCMYK":
			if err := convertImageSamples(ctx, &sd, objNr, comps, res, false); err != nil {
				res.ImagesSkipped = append(res.ImagesSkipped, fmt.Sprintf(
					"obj %d (CMYK): %v", objNr, err))
			} else {
				entry.Object = sd
			}
		default:
			res.ImagesSkipped = append(res.ImagesSkipped, fmt.Sprintf(
				"obj %d: espacio %q fuera del alcance", objNr, csName))
		}
	}
	return nil
}

// resolveColorSpace extrae la familia base del espacio y el número de
// componentes de muestra. Devuelve ("DeviceRGB", 3) etc.
func resolveColorSpace(ctx *model.Context, sd *types.StreamDict) (string, int, error) {
	csObj, ok := sd.Find("ColorSpace")
	if !ok {
		return "", 0, fmt.Errorf("sin /ColorSpace")
	}

	obj := csObj
	if ir, ok := csObj.(types.IndirectRef); ok {
		// Dereference genérico: /ColorSpace puede apuntar a un Name, un
		// array ([/ICCBased n 0 R]) o un dict según el PDF.
		d, err := ctx.Dereference(ir)
		if err != nil {
			return "", 0, err
		}
		obj = d
	}

	switch cs := obj.(type) {
	case types.Name:
		name := string(cs)
		switch name {
		case "DeviceRGB", "RGB":
			return "DeviceRGB", 3, nil
		case "DeviceGray", "G":
			return "DeviceGray", 1, nil
		case "DeviceCMYK", "CMYK":
			return "DeviceCMYK", 4, nil
		case "Indexed":
			return "Indexed", 0, nil
		case "Separation":
			return "Separation", 0, nil
		case "CalRGB":
			return "CalRGB", 3, nil
		case "CalGray":
			return "DeviceGray", 1, nil
		default:
			return name, 0, nil
		}

	case types.Array:
		if len(cs) == 0 {
			return "", 0, fmt.Errorf("/ColorSpace array vacío")
		}
		first, err := ctx.Dereference(cs[0])
		if err != nil {
			return "", 0, err
		}
		name, ok := first.(types.Name)
		if !ok {
			return "", 0, fmt.Errorf("/ColorSpace primer elemento no es Name")
		}
		switch string(name) {
		case "Indexed":
			return "Indexed", 0, nil
		case "ICCBased":
			if len(cs) < 2 {
				return "", 0, fmt.Errorf("ICCBased sin stream")
			}
			iccObj, err := ctx.Dereference(cs[1])
			if err != nil {
				return "", 0, err
			}
			var stream types.StreamDict
			switch o := iccObj.(type) {
			case types.StreamDict:
				stream = o
			case *types.StreamDict:
				stream = *o
			default:
				return "ICCBased", 0, nil
			}
			if nV := stream.IntEntry("N"); nV != nil {
				switch *nV {
				case 1:
					return "DeviceGray", 1, nil
				case 3:
					return "ICCRGB", 3, nil
				case 4:
					return "ICCCMYK", 4, nil
				}
			}
			return "ICCBased", 0, nil
		case "Separation":
			return "Separation", 0, nil
		case "DeviceN":
			return "DeviceN", 0, nil
		case "DeviceRGB", "RGB":
			return "DeviceRGB", 3, nil
		case "DeviceGray", "G":
			return "DeviceGray", 1, nil
		case "DeviceCMYK", "CMYK":
			return "DeviceCMYK", 4, nil
		case "CalRGB":
			return "CalRGB", 3, nil
		case "CalGray":
			return "DeviceGray", 1, nil
		default:
			return string(name), 0, nil
		}

	default:
		return "", 0, fmt.Errorf("espacio de color no soportado: %T", cs)
	}
}

// convertImageSamples convierte un XObject /Image de 8bpc RGB/CMYK a gris.
// FlateDecode: reescritura directa de muestras; DCTDecode: JPEG stdlib.
func convertImageSamples(ctx *model.Context, sd *types.StreamDict, objNr, comps int, res *GrayResult, isRGB bool) error {
	wV := sd.IntEntry("Width")
	hV := sd.IntEntry("Height")
	if wV == nil || hV == nil {
		return fmt.Errorf("sin Width/Height")
	}
	w, h := *wV, *hV
	expected := w * h * comps

	if sd.HasSoleFilterNamed(filter_Flate) {
		if err := sd.Decode(); err != nil {
			return fmt.Errorf("decode: %w", err)
		}
		raw := sd.Content
		if len(raw) != expected {
			return fmt.Errorf("muestras: esperadas %d, decodificadas %d", expected, len(raw))
		}
		gray := make([]byte, w*h)
		for i := 0; i < w*h; i++ {
			if isRGB {
				r := float64(raw[i*3]) / 255
				g := float64(raw[i*3+1]) / 255
				b := float64(raw[i*3+2]) / 255
				y := rgbToGray(r, g, b)
				gray[i] = byte(y * 255)
			} else {
				c := float64(raw[i*4]) / 255
				m := float64(raw[i*4+1]) / 255
				yy := float64(raw[i*4+2]) / 255
				k := float64(raw[i*4+3]) / 255
				y := cmykToGray(c, m, yy, k)
				gray[i] = byte(y * 255)
			}
		}

		sd.Content = gray
		if err := sd.Encode(); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
		if err := setGrayColorSpace(sd); err != nil {
			return err
		}
		res.ImagesConverted++
		return nil
	}

	if sd.HasSoleFilterNamed(filter_DCT) {
		// JPEG: decodificar, convertir, re-encode como JPEG gris.
		img, err := jpeg.Decode(bytes.NewReader(sd.Raw))
		if err != nil {
			return fmt.Errorf("jpeg decode: %w", err)
		}
		bounds := img.Bounds()
		grayImg, ok := imgToGray(img, bounds)
		if !ok {
			return fmt.Errorf("conversión de pixel no soportada")
		}

		var out bytes.Buffer
		if err := jpeg.Encode(&out, grayImg, &jpeg.Options{Quality: 90}); err != nil {
			return fmt.Errorf("jpeg encode: %w", err)
		}

		sd.Raw = out.Bytes()
		sd.Content = nil
		length := int64(len(sd.Raw))
		sd.StreamLength = &length
		sd.Update("Length", types.Integer(length))
		if err := setGrayColorSpace(sd); err != nil {
			return err
		}
		res.ImagesConverted++
		return nil
	}

	return fmt.Errorf("filtros de imagen no convertibles en este objeto")
}

// filter symbols (via sin importar el package filter de pdfcpu).
const (
	filter_Flate = "FlateDecode"
	filter_DCT   = "DCTDecode"
)

// setGrayColorSpace ajusta el /ColorSpace del dict a Name("DeviceGray")
// y limpia Decode/SMask irrelevantes.
func setGrayColorSpace(sd *types.StreamDict) error {
	names := []string{"ColorSpace"}
	for _, k := range names {
		sd.Delete(k)
	}
	sd.Insert("ColorSpace", types.Name("DeviceGray"))
	return nil
}

// imgToGray convierte un image.Image genérico a un *image.Gray.
func imgToGray(img image.Image, bounds image.Rectangle) (*image.Gray, bool) {
	// Si ya es gris, tomar atajo.
	if g, ok := img.(*image.Gray); ok {
		return g, true
	}

	g := image.NewGray(bounds)
	b := bounds
	for yy := b.Min.Y; yy < b.Max.Y; yy++ {
		for xx := b.Min.X; xx < b.Max.X; xx++ {
			r, gg, bb, _ := img.At(xx, yy).RGBA() // 0..65535
			// BT.601: 0.299R + 0.587G + 0.114B ≈ (30R+59G+11B)/100.
			// Escala 16-bit: 65535*0.299 ≈ 19594 → divisor 257 ≈ (30R+59G+11B)/257*? redondeo limpio:
			y := uint8((int64(r)*30 + int64(gg)*59 + int64(bb)*11) / 25700)
			g.SetGray(xx, yy, color.Gray{Y: y})
		}
	}
	return g, true
}

func clamp255(v int64) int {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return int(v)
}
