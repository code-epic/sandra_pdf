// sandra_pdf — caja de herramientas PDF del ecosistema Sandra.
//
// Procesa, audita y manipula archivos PDF:
//   - división/unión de páginas (--pages/--merge)
//   - optimización (--optimize) y escala de grises (--grayscale)
//   - auditoría de seguridad (--audit: JS/OpenAction/Launch/EmbeddedFiles)
//   - metadata (--info/--set-meta)
//   - firma digital PAdES-like (--sign-cert/.pfx/.p12/.pem/.crt)
package main

import "github.com/code-epic/sandra_pdf/cmd"

func main() {
	cmd.Execute()
}
