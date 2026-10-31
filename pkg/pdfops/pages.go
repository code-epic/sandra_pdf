package pdfops

import (
	"fmt"
	"strconv"
	"strings"
)

// expandRange expande un token a páginas concretas. Formatos:
//
//	"-"    → todas las páginas
//	"7"    → página única
//	"5-"   → abierto desde 5 hasta el final
//	"1-7"  → rango inclusivo
//
// La validación de límites contra pageCount es estricta: cualquier índice
// fuera de [1, pageCount] produce error (evita silenciosamente truncar).
func expandRange(sep string, pageCount int) ([]int, error) {
	// "-" = todas las páginas.
	if sep == "-" {
		pages := make([]int, 0, pageCount)
		for p := 1; p <= pageCount; p++ {
			pages = append(pages, p)
		}
		return pages, nil
	}

	startStr, endStr, hasDash := strings.Cut(sep, "-")
	if !hasDash {
		// página única "7"
		start, err := strconv.Atoi(sep)
		if err != nil {
			return nil, fmt.Errorf("selector de página inválido: %q", sep)
		}
		return validateLoHi(start, start, pageCount)
	}

	start, err := strconv.Atoi(startStr)
	if err != nil {
		return nil, fmt.Errorf("límite inicial inválido: %q", sep)
	}

	// "5-" → abierto: hasta la última página.
	if endStr == "" {
		return validateLoHi(start, pageCount, pageCount)
	}

	end, err := strconv.Atoi(endStr)
	if err != nil {
		return nil, fmt.Errorf("límite final inválido: %q", sep)
	}
	return validateLoHi(start, end, pageCount)
}

// validateLoHi valida límites y expande [lo, hi].
func validateLoHi(lo, hi, pageCount int) ([]int, error) {
	if lo < 1 {
		return nil, fmt.Errorf("página inicial %d fuera de rango (mínimo 1)", lo)
	}
	if hi > pageCount {
		return nil, fmt.Errorf("página final %d fuera de rango (el documento tiene %d páginas)", hi, pageCount)
	}
	if lo > hi {
		return nil, fmt.Errorf("rango inválido: %d > %d", lo, hi)
	}
	pages := make([]int, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		pages = append(pages, p)
	}
	return pages, nil
}

// ParsePageSelectors parsea la expresión de páginas soportando:
//   - rangos consecutivos "1-7" (inclusivo en ambos extremos)
//   - listas discretas "1,7"
//   - combinaciones mixtas "1-3,5,8-10"
//   - rangos abiertos "5-" y "-" (todas)
//
// pageCount es el total real de páginas del documento; se valida estrictamente
// que toda página seleccionada esté en [1, pageCount]. Devuelve la secuencia en
// el orden provisto, sin duplicados (un intento repetido conserva su orden de
// primera aparición).
func ParsePageSelectors(expr string, pageCount int) ([]int, error) {
	return parse(expr, pageCount)
}

// parse extraída para poder testear manteniendo la firma pública limpia.
func parse(expr string, pageCount int) ([]int, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("selector de páginas vacío")
	}
	if pageCount <= 0 {
		return nil, fmt.Errorf("el documento no tiene páginas")
	}

	var sel []int
	seen := map[int]bool{}

	for _, tok := range strings.Split(expr, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			return nil, fmt.Errorf("token vacío en selector de páginas %q", expr)
		}

		pages, err := expandRange(tok, pageCount)
		if err != nil {
			return nil, err
		}

		for _, p := range pages {
			if seen[p] {
				continue
			}
			seen[p] = true
			sel = append(sel, p)
		}
	}

	if len(sel) == 0 {
		return nil, fmt.Errorf("selector %q no produjo páginas", expr)
	}
	return sel, nil
}

// PagesToSelection convierte una lista de números de página al formato
// selectPages de pdfcpu (ej. []string{"1", "2"}) — la API de pdfcpu acepta
// tanto strings por página como rangos; usamos listas explícitas para
// garantizar el orden provisto por el usuario.
func PagesToSelection(pages []int) []string {
	sel := make([]string, len(pages))
	for i, p := range pages {
		sel[i] = strconv.Itoa(p)
	}
	return sel
}
