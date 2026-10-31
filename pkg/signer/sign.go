// Package signer: incrustación de firmas digitales en PDF (PAdES-like)
// sobre github.com/digitorus/pdfsign.
package signer

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
)

// Options de la firma.
type Options struct {
	// Datos visibles del firmante (diccionario sig).
	Name        string
	Location    string
	Reason      string
	ContactInfo string

	// Firma de certificación vs aprobación.
	Certify bool // true = certification signature (DocMDP), false = aprobación

	// Apariencia.
	Visible    bool
	Page       int     // 1-indexed; 0 = última página
	LowerLeftX float64
	LowerLeftY float64
	UpperRightX float64
	UpperRightY float64
	// Image PNG (firma-sello). Si vacío y Visible=true se usa imagen
	// transparente 1x1 (widget criptográficamente activo, visualmente vacío).
	Image []byte
}

// PDFSigner frontend para firmar rutas de archivos.
type PDFSigner struct {
	cred *LoadResult
}

// New construye un firmante sobre credenciales cargadas.
func New(cred *LoadResult) *PDFSigner {
	return &PDFSigner{cred: cred}
}

// CertType fija adaptación prudente:
//   - Certify: certification signature (DocMDP: cambios bloqueados después de firma).
//   - default: approval signature.
func (o *Options) certType() sign.CertType {
	if o.Certify {
		return sign.CertificationSignature
	}
	return sign.ApprovalSignature
}

// SignFile adiciona la firma PDF en output.
func (s *PDFSigner) SignFile(inputPath, outputPath string, o Options) error {
	cred := s.cred
	if cred == nil || cred.PrivateKey == nil || cred.Cert == nil {
		return fmt.Errorf("credenciales no cargadas")
	}

	page := o.Page
	if page <= 0 {
		page = 1
	}

	sd := sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        o.Name,
				Location:    o.Location,
				Reason:      o.Reason,
				ContactInfo: o.ContactInfo,
				Date:        time.Now(),
			},
			CertType:   o.certType(),
			DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            cred.PrivateKey,
		Certificate:       cred.Cert,
		CertificateChains: [][]*x509.Certificate{cred.Chain},
		RevocationData:    revocation.InfoArchival{},
	}

	if o.Visible {
		imgData := o.Image
		if len(imgData) == 0 {
			imgData = transparentPixel()
		}
		sd.Appearance = sign.Appearance{
			Visible:     true,
			Page:        uint32(page),
			LowerLeftX:  o.LowerLeftX,
			LowerLeftY:  o.LowerLeftY,
			UpperRightX: o.UpperRightX,
			UpperRightY: o.UpperRightY,
			Image:       imgData,
		}
	}

	if err := sign.SignFile(inputPath, outputPath, sd); err != nil {
		return fmt.Errorf("firma del documento: %w", err)
	}
	return nil
}

// SignStreams firma byte-to-byte via archivos temporales pdfsign opere
// rutas físicas; para consumir ReadSeeker/Writer, esta capa es transparente.
func (s *PDFSigner) SignStreams(rsIn *os.File, wOut *os.File, o Options) error {
	return s.SignFile(rsIn.Name(), wOut.Name(), o)
}

// transparentPixel 1x1 RGBA-A0 (apariencia invisible pero criptoactiva).
func transparentPixel() []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 1, 1))
	img.SetNRGBA(0, 0, color.NRGBA{R: 0, G: 0, B: 0, A: 0})
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
