package ber

import (
	"bytes"
	"testing"
)

func TestDefiniteAndIndefiniteLength(t *testing.T) {
	// SEQUENCE { INTEGER 5, OCTET STRING "ab" } as DER, and the same with indefinite length
	// and a constructed (segmented) OCTET STRING.
	der := []byte{0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 'a', 'b'}
	berb := []byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x24, 0x80, 0x04, 0x01, 'a', 0x04, 0x01, 'b', 0x00, 0x00, 0x00, 0x00}
	for _, in := range [][]byte{der, berb} {
		n, rest, err := Parse(append(append([]byte{}, in...), 0xff))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(n.Raw, in) || !bytes.Equal(rest, []byte{0xff}) {
			t.Errorf("raw %x rest %x", n.Raw, rest)
		}
		v, err := n.Child(0).Int()
		if err != nil || v.Int64() != 5 {
			t.Errorf("int %v %v", v, err)
		}
		if string(n.Child(1).Bytes()) != "ab" {
			t.Errorf("octets %q", n.Child(1).Bytes())
		}
	}
}

func TestParseAllAllowsZeroPaddingOnly(t *testing.T) {
	der := []byte{0x04, 0x01, 'x'}
	if _, err := ParseAll(append(der, 0, 0, 0)); err != nil {
		t.Errorf("zero padding refused: %v", err)
	}
	if _, err := ParseAll(append(der, 0, 1)); err == nil {
		t.Error("trailing data accepted")
	}
}

func TestHighTagNumberAndNegativeInteger(t *testing.T) {
	n, _, err := Parse([]byte{0x9f, 0x81, 0x00, 0x01, 0x07})
	if err != nil || n.Class != ClassContext || n.Tag != 128 || !bytes.Equal(n.Value, []byte{7}) {
		t.Fatalf("%+v %v", n, err)
	}
	i, _, _ := Parse([]byte{0x02, 0x01, 0xff})
	if v, err := i.Int(); err != nil || v.Int64() != -1 {
		t.Errorf("got %v %v", v, err)
	}
}

func TestMalformedInputIsAnErrorNotAPanic(t *testing.T) {
	deep := bytes.Repeat([]byte{0x30, 0x80}, 200)
	for _, b := range [][]byte{nil, {0x30}, {0x30, 0x05, 0x01}, {0x04, 0x80, 0x00, 0x00}, {0x30, 0x85, 1, 2, 3, 4, 5}, {0x30, 0x80, 0x04}, deep} {
		if _, _, err := Parse(b); err == nil {
			t.Errorf("%x accepted", b)
		}
	}
}

func TestEncodeLengths(t *testing.T) {
	for _, l := range []int{0, 127, 128, 255, 256, 65535, 65536} {
		b := Encode(0x04, make([]byte, l))
		n, rest, err := Parse(b)
		if err != nil || len(rest) != 0 || len(n.Value) != l {
			t.Errorf("length %d: %v", l, err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x05})
	f.Fuzz(func(t *testing.T, b []byte) {
		n, rest, err := Parse(b)
		if err == nil && len(n.Raw)+len(rest) != len(b) {
			t.Fatalf("raw %d + rest %d != %d", len(n.Raw), len(rest), len(b))
		}
	})
}
