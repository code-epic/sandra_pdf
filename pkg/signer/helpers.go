package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

// pkcs12ToPEM decompone el contenedor PKCS#12 a bloques PEM.
func pkcs12ToPEM(pfxData []byte, password string) ([]*pem.Block, error) {
	blocks, err := pkcs12.ToPEM(pfxData, password)
	if err != nil {
		return nil, err
	}
	return blocks, nil
}

// pemBlock devuelve el próximo bloque PEM; nil al agotarlo.
func pemBlock(data []byte) (*pem.Block, []byte) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, nil
	}
	return b, rest
}

// parsePEMKey interpreta el bloque PEM de clave.
// Soportado: PKCS#8 (llano y cifrado "ENCRYPTED PRIVATE KEY"), PKCS#1 RSA,
// EC llana. Las claves PEM legacy cifradas (Proc-Type: 4,ENCRYPTED) no se
// descifran: se reporta acción clara al usuario.
func parsePEMKey(block *pem.Block, password string) (crypto.PrivateKey, error) {
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("clave PKCS#8 cifrada no soportada aquí: decífrala previamente (openssl pkey -in key.pem) o usa .pfx")

	case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY":
		if len(block.Headers) > 0 {
			if _, enc := block.Headers["Proc-Type"]; enc {
				return nil, errors.New("clave PEM legacy cifrada no soportada: decífrala previamente (openssl pkey) o usa .pfx")
			}
		}
		return parsePrivateKey(block.Bytes)

	default:
		return nil, fmt.Errorf("tipo de bloque PEM inesperado: %q", block.Type)
	}
}

// Describe resumen legible de credenciales para el CLI.
func (lr *LoadResult) Describe() string {
	c := lr.Cert
	var b strings.Builder
	fmt.Fprintf(&b, "Sujeto: %s", c.Subject.String())
	if c.Subject.CommonName != "" {
		fmt.Fprintf(&b, " (CN=%s)", c.Subject.CommonName)
	}
	fmt.Fprintf(&b, " | Emisor: %s", c.Issuer.String())
	fmt.Fprintf(&b, " | Vigencia: %s → %s",
		c.NotBefore.Format("2006-01-02"), c.NotAfter.Format("2006-01-02"))
	fmt.Fprintf(&b, " | Algoritmo: %s | Cadena: %d cert(s)",
		keyAlg(c), len(lr.Chain))
	return b.String()
}

func keyAlg(c *x509.Certificate) string {
	switch c.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	case x509.DSA:
		return "DSA"
	}
	return "desconocido"
}
