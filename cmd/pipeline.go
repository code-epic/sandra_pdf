package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/code-epic/sandra_pdf/pkg/metadata"
	"github.com/code-epic/sandra_pdf/pkg/pdfops"
	"github.com/code-epic/sandra_pdf/pkg/security"
	"github.com/code-epic/sandra_pdf/pkg/signer"
)

// runPipeline ejecuta las operaciones solicitadas en este orden:
//
//  1. pages / merge          → transformación estructural
//  2. grayscale              → transformación de color
//  3. optimize               → limpieza pdfcpu
//  4. set-meta               → mutación de InfoDict (+ patch incremental)
//  5. escritura del buffer   → disco (tmp si firma: SignFile necesita rutas)
//  6. sign                   → firma digital (última escritura: append incremental)
//  7. audit / info           → reporte sobre el documento FINAL en disco
func runPipeline() error {
	inputs := splitList(o.input)

	// ---- Buffer de trabajo -------------------------------------------
	var buf []byte

	switch {
	case o.merge:
		// merge de múltiples entradas en orden provisto.
		readers := make([]io.ReadSeeker, len(inputs))
		for i, p := range inputs {
			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("merge: %w", err)
			}
			readers[i] = bytes.NewReader(data)
		}
		merged := &bytes.Buffer{}
		if err := pdfops.Merge(readers, merged); err != nil {
			return fmt.Errorf("merge: %w", err)
		}
		buf = merged.Bytes()

	default:
		data, err := os.ReadFile(inputs[0])
		if err != nil {
			return err
		}
		buf = data

		// --pages: selección de páginas.
		if o.pages != "" {
			buf, err = extractPages(buf, inputs[0])
			if err != nil {
				return err
			}
		}
	}

	// ---- grayscale ----------------------------------------------------
	if o.grayscale {
		rs := bytes.NewReader(buf)
		out := &bytes.Buffer{}
		res, err := pdfops.Grayscale(rs, out)
		if err != nil {
			return fmt.Errorf("grayscale: %w", err)
		}
		buf = out.Bytes()
		fmt.Fprintf(os.Stderr, "[grayscale] páginas=%d streams=%d imágenes=%d saltadas=%d\n",
			res.PagesProcessed, res.StreamsRewritten, res.ImagesConverted, len(res.ImagesSkipped))
		for _, skip := range res.ImagesSkipped {
			fmt.Fprintf(os.Stderr, "[grayscale]   ∅ %s\n", skip)
		}
	}

	// ---- optimize -----------------------------------------------------
	if o.optimize {
		rs := bytes.NewReader(buf)
		out := &bytes.Buffer{}
		if err := pdfops.Optimize(rs, out); err != nil {
			return fmt.Errorf("optimize: %w", err)
		}
		buf = out.Bytes()
	}

	// ---- set-meta -----------------------------------------------------
	if hasMeta() {
		mf, err := collectMetaFields()
		if err != nil {
			return err
		}
		rs := bytes.NewReader(buf)
		out := &bytes.Buffer{}
		if err := metadata.SetMetadata(rs, out, mf); err != nil {
			return fmt.Errorf("set-meta: %w", err)
		}
		buf = out.Bytes()
	}

	// ---- Escritura en disco (tmp si firma) ----------------------------
	// Regla: se escribe cuando hay operaciones transformadoras o cuando el
	// usuario proveyó --output. Para consultas puras (--audit/--info sin
	// transformaciones) no se produce archivo.
	targetPath := o.output
	tmpPath := ""
	if hasWriteOps() || o.signCert != "" || o.output != "" {
		if o.signCert != "" {
			tmpPath = targetPath + ".sandra.tmp"
			if err := os.WriteFile(tmpPath, buf, 0o644); err != nil {
				return err
			}
			defer func() { _ = os.Remove(tmpPath) }()
		} else {
			if err := pdfops.SaveFile(targetPath, buf); err != nil {
				return err
			}
		}
	}

	// ---- Firma digital -------------------------------------------------
	if o.signCert != "" {
		cred, err := signer.LoadCredentials(o.signCert, o.signKey, o.signPass)
		if err != nil {
			return fmt.Errorf("firma: %w", err)
		}
		signOpts, err := signOptions()
		if err != nil {
			return err
		}
		s := signer.New(cred)
		if err := s.SignFile(tmpPath, targetPath, *signOpts); err != nil {
			return fmt.Errorf("firma: %w", err)
		}
		if st, err := os.Stat(targetPath); err == nil {
			fmt.Fprintf(os.Stderr, "[firma] %s\n[firma] salida=%s (%s)\n", cred.Describe(), targetPath, metadata.HumanSize(st.Size()))
		}
	}

	if targetPath != "" {
		if st, statErr := os.Stat(targetPath); statErr == nil {
			fmt.Fprintf(os.Stderr, "[ok] %s (%s)\n", targetPath, metadata.HumanSize(st.Size()))
		} else {
			fmt.Fprintln(os.Stderr, "[ok]")
		}
	}

	// ---- Auditoría / info sobre el documento FINAL ---------------------
	finalPath := targetPath
	if !SignActive() {
		// sin firma: el reporte puede correr sobre el buffer directamente
		// si no hubo operaciones de escritura (documento original intacto).
		if !hasWriteOps() {
			finalPath = inputs[0]
		}
	}

	if o.audit {
		f, err := os.Open(finalPath)
		if err != nil {
			return err
		}
		defer f.Close()
		rep, err := security.Audit(finalPath, f)
		if err != nil {
			return fmt.Errorf("audit: %w", err)
		}
		if o.json {
			data, err := security.ReportJSON(rep)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
		} else {
			security.PrintReport(os.Stdout, rep)
		}
	}

	if o.info {
		info, err := metadata.InspectFile(finalPath)
		if err != nil {
			return fmt.Errorf("info: %w", err)
		}
		if o.json {
			data, err := metadata.InspectJSON(info)
			if err != nil {
				return err
			}
			fmt.Println(string(data))
		} else {
			metadata.InfoTable(os.Stdout, info)
		}
	}

	return nil
}

// extractPages aplica --pages sobre el buffer.
func extractPages(buf []byte, srcName string) ([]byte, error) {
	// 1) paginar numéricamente para validación estricta de límites.
	tmp := filepath.Join(os.TempDir(), "sandrapdf-pages-count.pdf")
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return nil, err
	}
	pc, err := pdfops.PageCount(bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("--pages: contando páginas de %s: %w", srcName, err)
	}

	pages, err := pdfops.ParsePageSelectors(o.pages, pc)
	if err != nil {
		return nil, fmt.Errorf("--pages (%s, %d página(s)): %w", o.pages, pc, err)
	}

	out := &bytes.Buffer{}
	if err := pdfops.CollectPages(bytes.NewReader(buf), out, pages); err != nil {
		return nil, fmt.Errorf("--pages: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[pages] %d/%d página(s) → %v\n", len(pages), pc, pages)
	return out.Bytes(), nil
}

// collectMetaFields respeta los atajos --meta-* y pares --set-meta.
func collectMetaFields() (*metadata.MetaFields, error) {
	mf, err := metadata.ParseSetMeta(o.setMeta)
	if err != nil {
		return nil, err
	}
	// atajos: sobreescriben los pares si hay conflicto.
	if o.metaTitle != "" {
		mf.Title = o.metaTitle
	}
	if o.metaAuthor != "" {
		mf.Author = o.metaAuthor
	}
	if o.metaSubject != "" {
		mf.Subject = o.metaSubject
	}
	if o.metaKeyword != "" {
		mf.Keywords = o.metaKeyword
	}
	if o.metaCreator != "" {
		mf.Creator = o.metaCreator
	}
	return mf, nil
}

// signOptions construye signer.Options desde flags.
func signOptions() (*signer.Options, error) {
	s := &signer.Options{
		Name:        o.signName,
		Reason:      o.signReason,
		Location:    o.signLoc,
		Visible:     o.signVisible,
		Page:        o.signPage,
	}

	if o.signVisible && o.signRect != "" {
		vals := strings.Split(o.signRect, ",")
		if len(vals) != 4 {
			return nil, fmt.Errorf("--sign-rect: formato esperado \"x1,y1,x2,y2\"")
		}
		var nums [4]float64
		for i, v := range vals {
			n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err != nil {
				return nil, fmt.Errorf("--sign-rect: valor %q inválido", v)
			}
			nums[i] = n
		}
		s.LowerLeftX, s.LowerLeftY = nums[0], nums[1]
		s.UpperRightX, s.UpperRightY = nums[2], nums[3]
	}

	if o.signImage != "" {
		img, err := os.ReadFile(o.signImage)
		if err != nil {
			return nil, fmt.Errorf("--sign-image: %w", err)
		}
		s.Image = img
	}

	return s, nil
}

// SignActive derivación para reusabilidad de specs.
func SignActive() bool { return o.signCert != "" }

// hasWriteOps ¿hubo operaciones quelinkplain write el buffer?.
func hasWriteOps() bool {
	return o.pages != "" || o.merge || o.optimize || o.grayscale || hasMeta()
}
