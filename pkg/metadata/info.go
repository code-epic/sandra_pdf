// Package metadata ofrece inspección (--info) y mutación (--set-meta) del
// diccionario de información (InfoDict) del PDF.
//
// Limitación técnica conocida y resuelta: el pipeline de escritura de pdfcpu
// SOBREESCRIBE Producer/CreationDate/ModDate con sus propios valores en cada
// pasada completa (pkg/pdfcpu/info.go ensureInfoDict). Para respetar esos
// campos solicitados por el usuario, SetMetadata aplica una segunda fase
// (patchHardFields) con una actualización incremental textual que sustituye
// el InfoDict referenciado por el trailer (spec PDF §7.5.6 "Incremental updates").
package metadata

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// Info resumen de inspección de un PDF.
type Info struct {
	FileName         string            `json:"archivo"`
	SizeBytes        int64             `json:"tamanoBytes"`
	SizeHuman        string            `json:"tamano"`
	Version          string            `json:"versionPDF"`
	PageCount        int               `json:"paginas"`
	Title            string            `json:"titulo,omitempty"`
	Author           string            `json:"autor,omitempty"`
	Subject          string            `json:"asunto,omitempty"`
	Keywords         []string          `json:"palabrasClave,omitempty"`
	Creator          string            `json:"creador,omitempty"`
	Producer         string            `json:"productor,omitempty"`
	CreationDate     string            `json:"creacion,omitempty"`
	ModDate          string            `json:"modificacion,omitempty"`
	Linearized       bool              `json:"linealizado,omitempty"`
	Signatures       bool              `json:"conFirmas,omitempty"`
	Form             bool              `json:"conFormularios,omitempty"`
	UsingObjectStm   bool              `json:"usaObjectStreams,omitempty"`
	UsingXRefStreams bool              `json:"usaXrefStreams,omitempty"`
	Watermarked      bool              `json:"conMarcaAgua,omitempty"`
	Properties       map[string]string `json:"propiedades,omitempty"`
}

// HumanSize formatea bytes a KB/MB/GB legibles (base binaria).
func HumanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// pdfcpuConf configuración tolerante aislada del config-dir.
func pdfcpuConf() *model.Configuration {
	api.DisableConfigDir()
	c := model.NewDefaultConfiguration()
	c.ValidationMode = model.ValidationRelaxed
	return c
}

// InspectFile genera el resumen --info desde un archivo en disco.
func InspectFile(path string) (*Info, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := Inspect(path, f)
	if err != nil {
		return nil, err
	}
	info.SizeBytes = st.Size()
	info.SizeHuman = HumanSize(st.Size())
	return info, nil
}

// Inspect genera el resumen --info desde un ReadSeeker.
func Inspect(fileName string, rs io.ReadSeeker) (*Info, error) {
	conf := pdfcpuConf()
	conf.Cmd = model.LISTINFO

	pdfInfo, err := api.PDFInfo(rs, fileName, nil, false, conf)
	if err != nil {
		return nil, err
	}

	return &Info{
		FileName:         fileName,
		Version:          pdfInfo.Version,
		PageCount:        pdfInfo.PageCount,
		Title:            pdfInfo.Title,
		Author:           pdfInfo.Author,
		Subject:          pdfInfo.Subject,
		Keywords:         pdfInfo.Keywords,
		Creator:          pdfInfo.Creator,
		Producer:         pdfInfo.Producer,
		CreationDate:     pdfInfo.CreationDate,
		ModDate:          pdfInfo.ModificationDate,
		Linearized:       pdfInfo.Linearized,
		Signatures:       pdfInfo.Signatures,
		Form:             pdfInfo.Form,
		UsingObjectStm:   pdfInfo.UsingObjectStreams,
		UsingXRefStreams: pdfInfo.UsingXRefStreams,
		Watermarked:      pdfInfo.Watermarked,
		Properties:       pdfInfo.Properties,
	}, nil
}

// InspectJSON serializa el resumen --info a JSON.
func InspectJSON(info *Info) ([]byte, error) {
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	return b, nil
}

// InfoTable escribe el resumen legible por humanos.
func InfoTable(w io.Writer, i *Info) {
	fmt.Fprintln(w, "===============================================")
	fmt.Fprintln(w, " INFORMACIÓN DEL PDF — sandra_pdf")
	fmt.Fprintln(w, "===============================================")
	fmt.Fprintf(w, " Archivo:    %s\n", i.FileName)
	fmt.Fprintf(w, " Tamaño:     %s (%d bytes)\n", i.SizeHuman, i.SizeBytes)
	fmt.Fprintf(w, " Versión:    %s\n", i.Version)
	fmt.Fprintf(w, " Páginas:    %d\n", i.PageCount)
	fmt.Fprintln(w, "-----------------------------------------------")
	fmt.Fprintf(w, " Título:     %s\n", i.Title)
	fmt.Fprintf(w, " Autor:      %s\n", i.Author)
	fmt.Fprintf(w, " Asunto:     %s\n", i.Subject)
	if len(i.Keywords) > 0 {
		fmt.Fprintf(w, " Palabras:   %s\n", strings.Join(i.Keywords, ", "))
	}
	fmt.Fprintf(w, " Creator:    %s\n", i.Creator)
	fmt.Fprintf(w, " Producer:   %s\n", i.Producer)
	fmt.Fprintf(w, " Creación:   %s\n", i.CreationDate)
	fmt.Fprintf(w, " Modificación: %s\n", i.ModDate)
	fmt.Fprintln(w, "-----------------------------------------------")
	if i.Linearized {
		fmt.Fprintln(w, " Linealizado: sí (carga progresiva)")
	}
	if i.Signatures {
		fmt.Fprintln(w, " Firmas:     sí")
	}
	if i.Form {
		fmt.Fprintln(w, " Formularios: sí")
	}
	if i.Watermarked {
		fmt.Fprintln(w, " Marca de agua: sí")
	}
	if len(i.Properties) > 0 {
		for k, v := range i.Properties {
			fmt.Fprintf(w, " Prop:       %s = %s\n", k, v)
		}
	}
	fmt.Fprintln(w, "===============================================")
}
