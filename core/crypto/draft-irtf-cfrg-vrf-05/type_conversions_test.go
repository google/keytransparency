package vrf

import (
	"bytes"
	"testing"
)

func TestI2OSP(t *testing.T) {
	for _, tc := range []struct {
		x, xLen int
		want    []byte
	}{
		{x: 1, xLen: 1, []byte(0x01)},
		{x: 2, xLen: 1, []byte(0x02)},
	} {
		if got := I2OSP(tc.x, tc.xLen); !bytes.Equal(got, tc.want) {
			t.Errorf("I2OSP(%v, %v): %v, want %v", tc, x, tc.xLen, got, tc.want)
		}
	}
}
