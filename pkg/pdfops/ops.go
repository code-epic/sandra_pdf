package pdfops

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// confRelaxed devuelve una configuración tolerante (los PDF del mundo real
// a veces violan el RFC) y aislada del config-dir del usuario: sandra_pdf
// nunca debe escribir ~/.pdfcpu.
func confRelaxed() *model.Configuration {
	api.DisableConfigDir()
	c := model.NewDefaultConfiguration()
	c.ValidationMode = model.ValidationRelaxed
	return c
}

// --- Operaciones núcleo (todo en memoria: io.ReadSeeker/Writer) ---

// Optimize limpia streams no utilizados, comprime fuentes y objetos huérfanos
// mediante el pipeline interno de pdfcpu (dedup de recursos, consolidación).
//
// Pipeline explícito (equivale a api.Optimize) en dos pasos necesarios:
//   - EnsurePageCount: ReadContext no valida y PageCount queda en 0, por lo
//     que OptimizeXRefTable terminaría temprano sin optimizar nada.
//   - ValidateContext: la validación materializa estado de recursos/fuentes
//     que el dedup de OptimizeContext necesita. Sin ella el dedup rompe las
//     referencias de fuente (texto ilegible) y los XObjects.
func Optimize(rs io.ReadSeeker, w io.Writer) error {
	c := confRelaxed()
	c.Cmd = model.OPTIMIZE
	ctx, err := api.ReadContext(rs, c)
	if err != nil {
		return err
	}
	if err := ctx.XRefTable.EnsurePageCount(); err != nil {
		return err
	}
	if err := api.ValidateContext(ctx); err != nil {
		return err
	}
	if err := api.OptimizeContext(ctx); err != nil {
		return err
	}
	return api.WriteContext(ctx, w)
}

// CollectPages extrae la lista de páginas ya parseada y validada
// (expresión "1-3,5,8-10" resuelta con ParsePageSelectors) y produce un
// nuevo PDF con solo esas páginas, respetando el orden provisto.
func CollectPages(rs io.ReadSeeker, w io.Writer, pages []int) error {
	c := confRelaxed()
	c.Cmd = model.COLLECT
	return api.Collect(rs, w, PagesToSelection(pages), c)
}

// MergeFilesFiles permite proporcionar rutas de archivos para fusión.
func MergeFiles(inFiles []string, w io.Writer) error {
	if len(inFiles) < 2 {
		return fmt.Errorf("merge requiere al menos 2 archivos de entrada (recibidos %d)", len(inFiles))
	}
	readers := make([]io.ReadSeeker, len(inFiles))
	for i, f := range inFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("leyendo %s: %w", f, err)
		}
		readers[i] = bytes.NewReader(data)
	}
	return Merge(readers, w)
}

// Merge concatena los PDFs provistos en orden, hacia w.
func Merge(readers []io.ReadSeeker, w io.Writer) error {
	if len(readers) < 2 {
		return fmt.Errorf("merge requiere al menos 2 archivos de entrada (recibidos %d)", len(readers))
	}
	c := confRelaxed()
	c.Cmd = model.MERGECREATE
	return api.MergeRaw(readers, w, false, c)
}

// PageCount cuenta las páginas de los datos provistos.
func PageCount(rs io.ReadSeeker) (int, error) {
	c := confRelaxed()
	return api.PageCount(rs, c)
}

// --- Utilidades de archivo ---

// LoadFile lee todo el contenido del archivo a memoria.
func LoadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// SaveFile escribe datos al disco creando directorios padre cuando falten.
func SaveFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}

// SplitInputs separa la lista de inputs de la línea de comandos ("a.pdf,b.pdf").
func SplitInputs(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
