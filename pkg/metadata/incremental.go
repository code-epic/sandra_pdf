package metadata

import (
	"bytes"
	"fmt"
	"strconv"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// ============================================================================
// Actualización incremental textual para mutar campos del InfoDict que
// pdfcpu sobrescribe en cada escritura completa.
//
// Formato aplicado (PDF 32000 §7.5.6):
//
//	<obj nuevo "N 0 obj <<...>> endobj">
//	xref
//	N 1
//	<offset 20 bytes> 65535 n
//	trailer
//	<< /Root R 0 R /Size S [/ID x x] /Prev prevXrefOffset >>
//	startxref
//	<offset del nuevo xref>
//	%%EOF
//
// Los lectores conformantes toman el ÚLTIMO xref/trailer como definición
// activa: el /Info del nuevo trailer apunta al objeto nuevo. Los bytes del
// documento original permanecen intactos (propiedad importante cuando el
// documento está firmado).
// ============================================================================

// patchHardFields reemplaza el InfoDict del PDF (bytes) con un dict nuevo
// que contiene todas las entradas existentes + los campos "hard" provistos.
func patchHardFields(data []byte, hard map[string]string) ([]byte, error) {
	if len(hard) == 0 {
		return data, nil
	}

	// 1) Leer contexto (tolerante) para: Info, Root, ID, Size, MaxObjNr.
	conf := pdfcpuConf()
	ctx, err := api.ReadContext(bytes.NewReader(data), conf)
	if err != nil {
		return nil, fmt.Errorf("lectura para patch incremental: %w", err)
	}
	if ctx.Info == nil {
		return nil, fmt.Errorf("el documento no tiene InfoDict (aplicar --set-meta con campos estándar primero)")
	}

	infoObj, err := ctx.DereferenceDict(*ctx.Info)
	if err != nil || infoObj == nil {
		return nil, fmt.Errorf("InfoDict no derefenciable: err=%v", err)
	}

	// 2) InfoDict destino: preserva entradas existentes, sobrescribe hard.
	target := types.Dict{}
	for k, v := range infoObj {
		target[k] = v
	}

	// Escapes idénticos al pipeline interno de pdfcpu (UTF-16 con BOM,
	// byte-swapping y \-escaping según Spec §7.9.2.2).
	for k, v := range hard {
		escaped, err := types.EscapedUTF16String(v)
		if err != nil {
			return nil, fmt.Errorf("(hard) %s: %w", k, err)
		}
		target[k] = types.StringLiteral(*escaped)
	}

	// 3) Número del objeto nuevo.
	newObjNr := ctx.MaxObjNr + 1

	// 4) Serializar el dict. Dict.String() produce sintaxis PDF válida
	// (los StringLiteral incluyen sus paréntesis verbatim).
	dictStr := target.String()

	// 5) Ensamblar la actualización incremental.
	objOffset := int64(len(data)) // el objeto nuevo arranca justo tras los datos previos

	objBytes := bytes.NewBuffer(nil)
	fmt.Fprintf(objBytes, "%d 0 obj\n", newObjNr)
	objBytes.WriteString(dictStr)
	objBytes.WriteString("\nendobj\n")

	xrefStart := objOffset + int64(objBytes.Len())

	size := pageSize(ctx)
	if size < newObjNr+1 {
		size = newObjNr + 1
	}

	var tr bytes.Buffer
	tr.WriteString("trailer\n<< /Root ")
	tr.WriteString(ctx.Root.PDFString())
	tr.WriteString(fmt.Sprintf(" /Size %d ", size))
	if ctx.ID != nil && len(ctx.ID) == 2 {
		tr.WriteString("/ID [")
		tr.WriteString(ctx.ID[0].PDFString())
		tr.WriteString(" ")
		tr.WriteString(ctx.ID[1].PDFString())
		tr.WriteString("] ")
	}
	if prev := lastStartXref(data); prev > 0 {
		tr.WriteString(fmt.Sprintf("/Prev %d ", prev))
	}
	tr.WriteString(">>\nstartxref\n")
	tr.WriteString(fmt.Sprintf("%d\n%%%%EOF\n", xrefStart))

	out := &bytes.Buffer{}
	out.Grow(len(data) + objBytes.Len() + tr.Len() + 64)
	out.Write(data)
	out.Write(objBytes.Bytes())
	out.WriteString(fmt.Sprintf("xref\n%d 1\n", newObjNr))
	out.WriteString(fmt.Sprintf("%010d 65535 n \n", objOffset))
	out.Write(tr.Bytes())

	return out.Bytes(), nil
}

// lastStartXref escanea desde el final buscando "startxref" y devuelve
// el offset numérico anexo (offset del xref vigente). 0 si no existe.
func lastStartXref(data []byte) int64 {
	tail := data
	if len(tail) > 4096 {
		tail = tail[len(tail)-4096:]
	}
	pos := bytes.LastIndex(tail, []byte("startxref"))
	if pos < 0 {
		return 0
	}
	after := tail[pos+len("startxref"):]
	i := 0
	for i < len(after) && (after[i] == ' ' || after[i] == '\n' || after[i] == '\r') {
		i++
	}
	digits := 0
	for i+digits < len(after) && after[i+digits] >= '0' && after[i+digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return 0
	}
	v, err := strconv.ParseInt(string(after[i:i+digits]), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// pageSize devuelve /Size del trailer actual (XRefTable.Size *int).
func pageSize(ctx *model.Context) int {
	if ctx.Size == nil {
		return 0
	}
	return *ctx.Size
}
