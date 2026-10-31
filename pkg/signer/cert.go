// Package signer maneja certificados X.509 y claves privadas para firmar
// PDFs digitalmente (PAdES-style con pdfsign).
//
// Compatibilidad de contenedores:
//   - .pfx / .p12 (PKCS#12): certificado + clave + cadena en un archivo.
//   - .pem / .crt / .cer (X.509): certificado(s) en PEM o DER.
//     La clave privada viene aparte vía .pem (PKCS#1/8 o EC) o
//     espera embebida dentro del propio pem de cert (bundle).
package signer

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadResult materializa el par clave hoja + cadena de confianza.
type LoadResult struct {
	PrivateKey crypto.Signer
	Cert       *x509.Certificate   // certificado hoja (par de la clave)
	Chain      []*x509.Certificate // cadenas ordenadas: hoja → raíz
}

// LoadCredentials carga credenciales desde certPath (+ keyPath opcional).
// password pertenece al contenedor (.pfx/.p12) o a la clave PEM cifrada.
func LoadCredentials(certPath, keyPath, password string) (*LoadResult, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("leyendo certificado %s: %w", certPath, err)
	}

	ext := strings.ToLower(strings.TrimPrefix(extension(certPath), "."))
	switch ext {
	case "pfx", "p12", "p12b", "pkcs12":
		if keyPath != "" {
			return nil, errors.New("con contenedor .pfx/.p12 la clave va embebida: --sign-key no aplica")
		}
		return loadPKCS12(certData, password)
	case "pem", "crt", "cer", "crtx", "cert":
		if keyPath != "" {
			keyData, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, fmt.Errorf("leyendo clave %s: %w", keyPath, err)
			}
			return loadPEMSplit(certData, keyData, password)
		}
		// bundle pem: cert + opcionalmente "PRIVATE KEY" en el mismo archivo
		return loadPEMBundle(certData, password)
	default:
		return nil, fmt.Errorf("formato de certificado %q no soportado: use .pfx, .p12, .pem, .crt o .cer", ext)
	}
}

func extension(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[i:]
		}
	}
	return ""
}

// --- PKCS#12 ---------------------------------------------------------------

func loadPKCS12(pfxData []byte, password string) (*LoadResult, error) {
	blocks, err := pkcs12ToPEM(pfxData, password)
	if err != nil {
		// x/crypto/pkcs12 no decodifica PBES2 (por defecto en OpenSSL 3).
		// Dar经 claras: politica de conversión a PEM o re-export legacy.
		return nil, fmt.Errorf("decodificando PKCS#12: %w — este contenedor usa PBES2 "+
			"(por defecto en OpenSSL 3+), no soportado aquí. Soluciones:\n"+
			"  1. Exportar a PEM: openssl pkcs12 -in f.pfx -nodes -out f.pem "+
			"y usarlo con --sign-cert f.pem\n"+
			"  2. Re-export en PBES1 legacy: openssl pkcs12 -export -legacy "+
			"-certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES", err)
	}

	var key crypto.PrivateKey
	var certs []*x509.Certificate

	for _, b := range blocks {
		switch {
		case strings.HasSuffix(b.Type, "PRIVATE KEY"):
			pk, err := parsePrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("clave en PFX: %w", err)
			}
			key = pk
		case b.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificado en PFX: %w", err)
			}
			certs = append(certs, cert)
		}
	}

	if key == nil {
		return nil, errors.New("el contenedor PKCS#12 no incluye la clave privada")
	}
	signerKey, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("la clave privada no implementa crypto.Signer")
	}

	leaf, chain, err := matchLeafAndChain(signerKey, certs)
	if err != nil {
		return nil, err
	}
	return &LoadResult{PrivateKey: signerKey, Cert: leaf, Chain: chain}, nil
}

// --- PEM -------------------------------------------------------------------

func loadPEMSplit(certData, keyData []byte, keyPassword string) (*LoadResult, error) {
	key, err := loadPrivateKeyBlock(keyData, keyPassword)
	if err != nil {
		return nil, err
	}
	signerKey, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("la clave privada no implementa crypto.Signer")
	}

	certs, err := parseCertsPEMOrDER(certData)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no hay certificados en el archivo de certificado")
	}

	leaf, chain, err := matchLeafAndChain(signerKey, certs)
	if err != nil {
		return nil, err
	}
	return &LoadResult{PrivateKey: signerKey, Cert: leaf, Chain: chain}, nil
}

func loadPEMBundle(data []byte, keyPassword string) (*LoadResult, error) {
	var key crypto.PrivateKey
	var certs []*x509.Certificate

	rest := data
	for {
		block, remain := pemBlock(rest)
		if block == nil {
			break
		}
		rest = remain

		switch {
		case strings.HasSuffix(block.Type, "PRIVATE KEY"):
			if key == nil {
				pk, err := parsePrivateKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("clave embebida: %w", err)
				}
				key = pk
			}
		case block.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificado PEM: %w", err)
			}
			certs = append(certs, c)
		}
	}

	if key == nil {
		return nil, errors.New("sin clave privada en el bundle PEM: provea --sign-key")
	}
	if len(certs) == 0 {
		return nil, errors.New("sin certificados en el bundle PEM")
	}

	signerKey, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("la clave privada no implementa crypto.Signer")
	}

	leaf, chain, err := matchLeafAndChain(signerKey, certs)
	if err != nil {
		return nil, err
	}
	return &LoadResult{PrivateKey: signerKey, Cert: leaf, Chain: chain}, nil
}

// parseCertsPEMOrDER admite PEM "CERTIFICATE" encadenado o DER crudo.
func parseCertsPEMOrDER(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	rest := data
	for {
		block, remain := pemBlock(rest)
		if block == nil {
			break
		}
		rest = remain
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("certificado PEM: %w", err)
			}
			certs = append(certs, c)
		}
	}

	if len(certs) == 0 {
		// Intento DER crudo.
		if der, err := x509.ParseCertificate(data); err == nil {
			certs = append(certs, der)
		}
	}
	return certs, nil
}

// loadPrivateKeyBlock carga la clave desde PEM (PKCS#1/8/EC, opcionalmente
// cifrada con la clave PEM legacy o PKCS#8).
func loadPrivateKeyBlock(data []byte, password string) (crypto.PrivateKey, error) {
	rest := data
	for {
		block, remain := pemBlock(rest)
		if block == nil {
			return nil, errors.New("no se encontró bloque PEM de clave privada")
		}
		rest = remain

		switch block.Type {
		case "RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			return parsePEMKey(block, password)
		}
	}
}

// --- Helpers ----------------------------------------------------------------

func matchLeafAndChain(key crypto.Signer, certs []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("serializando clave pública: %w", err)
	}

	var leaf *x509.Certificate
	for _, c := range certs {
		if cpub, err := x509.MarshalPKIXPublicKey(c.PublicKey); err == nil && bytes.Equal(cpub, pubDER) {
			leaf = c
			break
		}
	}
	if leaf == nil {
		return nil, nil, errors.New("el certificado hoja no coincide con la clave privada provista")
	}

	// Cadena ordenada hoja → raíz (excluye auto-firmados duplicados).
	chain := []*x509.Certificate{leaf}
	cur := leaf
	for {
		parentFound := false
		for _, c := range certs {
			if bytes.Equal(c.Raw, cur.Raw) {
				continue
			}
			if c.Subject.String() != cur.Issuer.String() {
				continue
			}
			if c.Subject.String() == cur.Subject.String() {
				continue // misma entidad (auto-firmada): sin incentivos
			}
			if err := cur.CheckSignatureFrom(c); err == nil {
				chain = append(chain, c)
				cur = c
				parentFound = true
				break
			}
		}
		if !parentFound {
			break
		}
	}
	return leaf, chain, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("formato de clave privada no reconocido")
}
