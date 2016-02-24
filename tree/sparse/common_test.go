package sparse

import (
	"testing"
)

func TestComputeNodeValues(t *testing.T) {
	bindex := "0100"
	leafHash := []byte("")
	neighbors := make([][]byte, 4)
	expected := []string{"0100", "010", "01", "0", ""}
	actual := NodeValues(bindex, leafHash, neighbors)
	if got, want := len(actual), len(expected); got != want {
		t.Errorf("len(%v)=%v, want %v", actual, got, want)
	}
}

func TestComputeEmptyNodeValues(t *testing.T) {
	bindex := "0100"
	leafHash := []byte("")
	neighbors := make([][]byte, 4)
	expected := []string{"0100", "010", "01", "0", ""}
	actual := NodeValues(bindex, leafHash, neighbors)
	if got, want := len(actual), len(expected); got != want {
		t.Errorf("len(%v)=%v, want %v", actual, got, want)
	}
}
