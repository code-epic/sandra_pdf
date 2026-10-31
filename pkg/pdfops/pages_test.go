package pdfops

import (
	"reflect"
	"testing"
)

func TestParsePageSelectors_RangosConsecutivos(t *testing.T) {
	got, err := parse("1-7", 10)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []int{1, 2, 3, 4, 5, 6, 7}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("esperado %v, obtenido %v", want, got)
	}
}

func TestParsePageSelectors_ListasDiscretas(t *testing.T) {
	got, err := parse("1,7", 10)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !reflect.DeepEqual(got, []int{1, 7}) {
		t.Fatalf("esperado [1 7], obtenido %v", got)
	}
}

func TestParsePageSelectors_Mixto(t *testing.T) {
	got, err := parse("1-3,5,8-10", 12)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	want := []int{1, 2, 3, 5, 8, 9, 10}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("esperado %v, obtenido %v", want, got)
	}
}

func TestParsePageSelectors_RangoAbierto(t *testing.T) {
	got, err := parse("8-", 10)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !reflect.DeepEqual(got, []int{8, 9, 10}) {
		t.Fatalf("esperado [8 9 10], obtenido %v", got)
	}
}

func TestParsePageSelectors_Todas(t *testing.T) {
	got, err := parse("-", 4)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !reflect.DeepEqual(got, []int{1, 2, 3, 4}) {
		t.Fatalf("esperado [1 2 3 4], obtenido %v", got)
	}
}

func TestParsePageSelectors_EliminaDuplicados(t *testing.T) {
	got, err := parse("2,1-3,2", 5)
	if err != nil {
		t.Fatalf("error inesperado: %v", err)
	}
	if !reflect.DeepEqual(got, []int{2, 1, 3}) {
		t.Fatalf("duplicados no eliminados: %v", got)
	}
}

func TestParsePageSelectors_FueraDeRango(t *testing.T) {
	if _, err := parse("1-12", 10); err == nil {
		t.Fatal("esperaba error por rango superior fuera de límites")
	}
	if _, err := parse("0-3", 10); err == nil {
		t.Fatal("esperaba error por página 0")
	}
}

func TestParsePageSelectors_ExpresionesInvalidas(t *testing.T) {
	for _, expr := range []string{"", "a-b", "1--3", "3-1", ",2", "2,", "1,2x", "1.5"} {
		if _, err := parse(expr, 10); err == nil {
			t.Fatalf("esperaba error para %q", expr)
		}
	}
}

func TestParsePageSelectors_DocumentoSinPaginas(t *testing.T) {
	if _, err := parse("1", 0); err == nil {
		t.Fatal("esperaba error con documento sin páginas")
	}
}
