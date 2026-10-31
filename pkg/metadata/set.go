package metadata

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
)

// MetaFields es el conjunto de campos estándar del InfoDict.
//
//   - Campos "soft" (Title, Author, Subject, Keywords, Creator): pdfcpu los
//     preserva en escritura normal → se aplican vía AddProperties.
//   - Campos "hard" (Producer, CreationDate, ModDate): pdfcpu los
//     sobrescribe en cada escritura completa → se aplican con el patch
//     incremental de incremental.go.
type MetaFields struct {
	Title, Author, Subject, Keywords string
	Creator                          string
	Producer, CreationDate, ModDate  string
}

// Empty indica si no hay campo definido.
func (mf *MetaFields) Empty() bool {
	return mf == nil || (mf.Title == "" && mf.Author == "" && mf.Subject == "" &&
		mf.Keywords == "" && mf.Creator == "" && mf.Producer == "" &&
		mf.CreationDate == "" && mf.ModDate == "")
}

// ParseSetMeta procesa pares "Clave=Valor" del flag --set-meta.
// Claves aceptadas (case-insensitive): Title, Author, Subject, Keywords,
// Creator, Producer, CreationDate, ModDate. Claves desconocidas → error.
func ParseSetMeta(pairs []string) (*MetaFields, error) {
	mf := &MetaFields{}
	for _, p := range pairs {
		key, val, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("--set-meta: par inválido %q (formato esperado Clave=Valor)", p)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			return nil, fmt.Errorf("--set-meta: clave vacía en %q", p)
		}
		switch strings.ToLower(key) {
		case "title":
			mf.Title = val
		case "author":
			mf.Author = val
		case "subject":
			mf.Subject = val
		case "keywords":
			mf.Keywords = val
		case "creator":
			mf.Creator = val
		case "producer":
			mf.Producer = val
		case "creationdate":
			mf.CreationDate = val
		case "moddate":
			mf.ModDate = val
		default:
			return nil, fmt.Errorf(
				"--set-meta: clave desconocida %q (válidas: Title, Author, Subject, Keywords, Creator, Producer, CreationDate, ModDate)", key)
		}
	}
	return mf, nil
}

// SetMetadata aplica los campos MetaFields al PDF y escribe el resultado
// en w. El flujo:
//
//  1. Campos "soft" vía pdfcpu AddProperties (escaping UTF-16 seguro).
//     Si no hay campos "soft", conserva el documento tal cual.
//  2. Campos "hard" vía patchHardFields (actualización incremental).
//
// Nota: sobre documentos firmados, la mutación vía actualización incremental
// mantiene la firma criptográficamente válida (los bytes firmados no cambian),
// pero los visores marcan el documento como modificado tras la firma.
func SetMetadata(rs io.ReadSeeker, w io.Writer, mf *MetaFields) error {
	if mf == nil || mf.Empty() {
		// Nada que hacer: passthrough.
		_, err := io.Copy(w, rs)
		return err
	}

	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// 1) Campos "soft" → pdfcpu.
	buf := &bytes.Buffer{}
	stdKeys := map[string]string{}
	if mf.Title != "" {
		stdKeys["Title"] = mf.Title
	}
	if mf.Author != "" {
		stdKeys["Author"] = mf.Author
	}
	if mf.Subject != "" {
		stdKeys["Subject"] = mf.Subject
	}
	if mf.Keywords != "" {
		stdKeys["Keywords"] = mf.Keywords
	}
	if mf.Creator != "" {
		stdKeys["Creator"] = mf.Creator
	}

	if len(stdKeys) > 0 {
		if err := api.AddProperties(rs, buf, stdKeys, pdfcpuConf()); err != nil {
			return fmt.Errorf("set-meta (soft): %w", err)
		}
	} else {
		if _, err := io.Copy(buf, rs); err != nil {
			return err
		}
	}

	// 2) Campos "hard" → patch incremental sobre el buffer.
	hard := map[string]string{}
	if mf.Producer != "" {
		hard["Producer"] = mf.Producer
	}
	if mf.CreationDate != "" {
		hard["CreationDate"] = mf.CreationDate
	}
	if mf.ModDate != "" {
		hard["ModDate"] = mf.ModDate
	}

	if len(hard) == 0 {
		_, err := w.Write(buf.Bytes())
		return err
	}

	patched, err := patchHardFields(buf.Bytes(), hard)
	if err != nil {
		return fmt.Errorf("set-meta (hard): %w", err)
	}
	_, err = w.Write(patched)
	return err
}
