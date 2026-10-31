// Package cmd configura el CLI de sandra_pdf:
// flags de línea de comandos y validación de combinaciones.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// appVersion versión del tool.
const appVersion = "0.1.0"

// opts agrupa todos los flags del CLI.
type opts struct {
	input       string
	output      string
	pages       string
	merge       bool
	audit       bool
	json        bool
	info        bool
	setMeta     []string
	metaTitle   string
	metaAuthor  string
	metaSubject string
	metaKeyword string
	metaCreator string
	optimize    bool
	grayscale   bool
	signCert    string
	signKey     string
	signPass    string
	signName    string
	signReason  string
	signLoc     string
	signVisible bool
	signPage    int
	signRect    string
	signImage   string
}

var o opts

// rootCmd comando raíz.
var rootCmd = &cobra.Command{
	Use:   "sandra_pdf",
	Short: "Procesa, audita y manipula archivos PDF (Sandra Ecosystem)",
	Long: `sandra_pdf — caja de herramientas PDF del ecosistema Sandra.

Operaciones (combinables, se ejecutan en orden):
  --pages         extraer/pegar selección de páginas: "1-3,5,8-10"
  --merge         unir múltiples --input en uno
  --optimize      limpieza de recursos y objetos huérfanos
  --grayscale     conversión de páginas/imágenes a DeviceGray
  --set-meta      metadata "Clave=Valor" (--set-meta Title=X --set-meta Author=Y)
  --audit         auditoría de seguridad (JS, OpenAction, Launch, ...)
  --info          información del documento
  --sign-cert     firma digital X.509 (.pfx/.p12/.pem/.crt)

Ejemplos:
  sandra_pdf -i doc.pdf -o extra.pdf --pages 1-3,5
  sandra_pdf -i a.pdf,b.pdf,c.pdf -o unido.pdf --merge
  sandra_pdf -i doc.pdf --audit
  sandra_pdf -i doc.pdf -o doc-verde.pdf --grayscale --optimize
  sandra_pdf -i doc.pdf --set-meta Title="Constancia 2026" -o meta.pdf
  sandra_pdf -i doc.pdf -o firmado.pdf --sign-cert firma.pfx --sign-password s3cret`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(); err != nil {
			return err
		}
		return runPipeline()
	},
}

// Execute entrada del binario.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	f := rootCmd.Flags()

	f.StringVarP(&o.input, "input", "i", "", "archivo(s) PDF de entrada (separados por coma para --merge)")
	f.StringVarP(&o.output, "output", "o", "", "PDF resultante")

	f.StringVarP(&o.pages, "pages", "p", "", "selector de páginas: \"1-7\", \"1,7\", \"1-3,5,8-10\", \"5-\", \"-\"")
	f.BoolVar(&o.merge, "merge", false, "unir todos los --input en --output (en orden)")

	f.BoolVar(&o.audit, "audit", false, "auditoría de seguridad (JS/OpenAction/Launch/EmbeddedFiles/...)")
	f.BoolVar(&o.json, "json", false, "salida estructurada JSON para --audit y --info")

	f.BoolVar(&o.info, "info", false, "información: tamaño, páginas, versión, metadata")

	f.StringArrayVar(&o.setMeta, "set-meta", nil, "metadata Clave=Valor (repeatable)")
	f.StringVar(&o.metaTitle, "meta-title", "", "atajo para Title")
	f.StringVar(&o.metaAuthor, "meta-author", "", "atajo para Author")
	f.StringVar(&o.metaSubject, "meta-subject", "", "atajo para Subject")
	f.StringVar(&o.metaKeyword, "meta-keywords", "", "atajo para Keywords")
	f.StringVar(&o.metaCreator, "meta-creator", "", "atajo para Creator")

	f.BoolVar(&o.optimize, "optimize", false, "optimización: streams no usados, fuentes, objetos huérfanos")
	f.BoolVar(&o.grayscale, "grayscale", false, "conversión de color a DeviceGray")

	f.StringVar(&o.signCert, "sign-cert", "", "certificado X.509:.pfx, .p12, .pem o .crt")
	f.StringVar(&o.signKey, "sign-key", "", "clave privada .pem (si no va embebida en .pfx)")
	f.StringVar(&o.signPass, "sign-password", "", "contraseña del contenedor/clave")
	f.StringVar(&o.signName, "sign-name", "", "nombre del firmante")
	f.StringVar(&o.signReason, "sign-reason", "", "motivo de la firma")
	f.StringVar(&o.signLoc, "sign-location", "", "ubicación del firmante")
	f.BoolVar(&o.signVisible, "sign-visible", false, "firma visible (widget annotation)")
	f.IntVar(&o.signPage, "sign-page", 1, "página de la firma visible (1-indexed)")
	f.StringVar(&o.signRect, "sign-rect", "", "rectángulo de la firma \"x1,y1,x2,y2\" (PDF points)")
	f.StringVar(&o.signImage, "sign-image", "", "PNG de la firma visible")
}

// validateFlags valida combinaciones y dependency de flags.
func validateFlags() error {
	if strings.TrimSpace(o.input) == "" {
		return fmt.Errorf("--input/-i es obligatorio")
	}

	inputs := splitList(o.input)
	if len(inputs) == 0 {
		return fmt.Errorf("--input no contiene archivos")
	}

	if o.merge && len(inputs) < 2 {
		return fmt.Errorf("--merge requiere al menos 2 archivos en --input (separados por coma)")
	}

	if o.pages != "" && o.merge {
		return fmt.Errorf("--pages y --merge son excluyentes")
	}
	if o.pages != "" && len(inputs) > 1 {
		return fmt.Errorf("--pages aplica solo a un único archivo de entrada")
	}

	if o.signCert == "" && (o.signKey != "" || o.signPass != "" || o.signVisible || o.signImage != "") {
		return fmt.Errorf("--sign-* requiere --sign-cert")
	}

	if o.signCert != "" && o.output == "" {
		return fmt.Errorf("la firma requiere --output")
	}

	if o.signRect != "" && !o.signVisible {
		return fmt.Errorf("--sign-rect requiere --sign-visible")
	}

	needWrite := o.pages != "" || o.merge || o.optimize || o.grayscale ||
		o.signCert != "" || hasMeta()
	if needWrite && o.output == "" {
		return fmt.Errorf("las operaciones de escritura (--pages/--merge/--optimize/--grayscale/--set-meta/--sign-*) requieren --output/-o")
	}

	if !needWrite && !o.audit && !o.info {
		return fmt.Errorf("no hay operación solicitada: use --pages, --merge, --optimize, --grayscale, --set-meta, --audit, --info o --sign-cert")
	}

	// checar existencia de todos los inputs temprano.
	for _, p := range inputs {
		if st, err := os.Stat(p); err != nil {
			return fmt.Errorf("entrada %q: %w", p, err)
		} else if st.IsDir() {
			return fmt.Errorf("entrada %q es un directorio", p)
		}
	}

	// cert válido a nivel filesystem temprano.
	if o.signCert != "" {
		if _, err := os.Stat(o.signCert); err != nil {
			return fmt.Errorf("--sign-cert %q: %w", o.signCert, err)
		}
	}
	if o.signKey != "" {
		if _, err := os.Stat(o.signKey); err != nil {
			return fmt.Errorf("--sign-key %q: %w", o.signKey, err)
		}
	}

	return nil
}

// splitList separa lista por coma con trim.
func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// hasMeta indica si hay metadata a aplicar.
func hasMeta() bool {
	return len(o.setMeta) > 0 || o.metaTitle != "" || o.metaAuthor != "" ||
		o.metaSubject != "" || o.metaKeyword != "" || o.metaCreator != ""
}
