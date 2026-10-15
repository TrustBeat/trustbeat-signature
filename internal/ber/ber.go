// Package ber reads ASN.1 BER (and so DER) into a tree that keeps every node's original bytes.
//
// Signatures must travel byte-exact: nothing read here is ever re-encoded. Go's encoding/asn1
// accepts DER only, but real CMS objects use BER indefinite lengths (three PDFs in the fixture
// corpus do), so the extractor walks the structure with this reader instead.
package ber

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Tag classes.
const (
	ClassUniversal   = 0
	ClassApplication = 1
	ClassContext     = 2
	ClassPrivate     = 3
)

// Universal tag numbers used by the extractor.
const (
	TagInteger     = 2
	TagOctetString = 4
	TagOID         = 6
	TagSequence    = 16
	TagSet         = 17
)

// maxDepth bounds nesting so hostile input cannot exhaust the stack.
const maxDepth = 64

// Node is one TLV. Raw is the complete original encoding (header, contents and, for indefinite
// length, the end-of-contents octets); Value is the contents octets of a primitive node.
type Node struct {
	Class       int
	Tag         int
	Constructed bool
	Indefinite  bool
	Raw         []byte
	Value       []byte
	Children    []*Node
}

// Parse reads exactly one node from b and returns it with the bytes that follow it.
func Parse(b []byte) (*Node, []byte, error) { return parse(b, 0) }

// ParseAll reads one node and fails if anything but zero padding follows it.
func ParseAll(b []byte) (*Node, error) {
	n, rest, err := Parse(b)
	if err != nil {
		return nil, err
	}
	for _, x := range rest {
		if x != 0 {
			return nil, errors.New("ber: trailing data after the object")
		}
	}
	return n, nil
}

func parse(b []byte, depth int) (*Node, []byte, error) {
	if depth > maxDepth {
		return nil, nil, errors.New("ber: nesting too deep")
	}
	if len(b) < 2 {
		return nil, nil, errors.New("ber: truncated header")
	}
	n := &Node{Class: int(b[0] >> 6), Constructed: b[0]&0x20 != 0}
	i := 1
	if t := int(b[0] & 0x1f); t != 0x1f {
		n.Tag = t
	} else {
		n.Tag = 0
		for {
			if i >= len(b) || i > 5 {
				return nil, nil, errors.New("ber: bad high tag number")
			}
			c := b[i]
			i++
			n.Tag = n.Tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return nil, nil, errors.New("ber: truncated length")
	}
	l0 := b[i]
	i++
	switch {
	case l0 == 0x80:
		if !n.Constructed {
			return nil, nil, errors.New("ber: indefinite length on a primitive")
		}
		n.Indefinite = true
		rest := b[i:]
		for {
			if len(rest) >= 2 && rest[0] == 0 && rest[1] == 0 {
				rest = rest[2:]
				break
			}
			c, r, err := parse(rest, depth+1)
			if err != nil {
				return nil, nil, err
			}
			n.Children = append(n.Children, c)
			rest = r
		}
		n.Raw = b[:len(b)-len(rest)]
		return n, rest, nil
	case l0 < 0x80:
		return finish(n, b, i, int(l0), depth)
	default:
		k := int(l0 & 0x7f)
		if k > 4 || i+k > len(b) {
			return nil, nil, errors.New("ber: unsupported length")
		}
		l := 0
		for j := 0; j < k; j++ {
			l = l<<8 | int(b[i+j])
		}
		return finish(n, b, i+k, l, depth)
	}
}

func finish(n *Node, b []byte, start, l, depth int) (*Node, []byte, error) {
	if l < 0 || start+l > len(b) {
		return nil, nil, errors.New("ber: length exceeds input")
	}
	n.Raw = b[:start+l]
	content := b[start : start+l]
	if !n.Constructed {
		n.Value = content
		return n, b[start+l:], nil
	}
	for len(content) > 0 {
		c, r, err := parse(content, depth+1)
		if err != nil {
			return nil, nil, err
		}
		n.Children = append(n.Children, c)
		content = r
	}
	return n, b[start+l:], nil
}

// Is reports whether the node has the given class and tag.
func (n *Node) Is(class, tag int) bool { return n != nil && n.Class == class && n.Tag == tag }

// Bytes returns the contents of an OCTET STRING, joining the segments of a constructed one.
func (n *Node) Bytes() []byte {
	if !n.Constructed {
		return n.Value
	}
	var out []byte
	for _, c := range n.Children {
		out = append(out, c.Bytes()...)
	}
	return out
}

// OID decodes an OBJECT IDENTIFIER node.
func (n *Node) OID() (asn1.ObjectIdentifier, error) {
	if !n.Is(ClassUniversal, TagOID) || n.Constructed {
		return nil, fmt.Errorf("ber: expected OID, got class %d tag %d", n.Class, n.Tag)
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(n.Raw, &oid); err != nil {
		return nil, err
	}
	return oid, nil
}

// Int decodes an INTEGER node.
func (n *Node) Int() (*big.Int, error) {
	if !n.Is(ClassUniversal, TagInteger) || n.Constructed || len(n.Value) == 0 {
		return nil, errors.New("ber: expected INTEGER")
	}
	v := new(big.Int).SetBytes(n.Value)
	if n.Value[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(n.Value))))
	}
	return v, nil
}

// Child returns the i-th child or nil.
func (n *Node) Child(i int) *Node {
	if n == nil || i < 0 || i >= len(n.Children) {
		return nil
	}
	return n.Children[i]
}

// Encode writes a definite-length DER header for the given identifier octet around contents.
// Used only for the few wrappers the extractor rebuilds; the contents are original bytes.
func Encode(identifier byte, contents []byte) []byte {
	l := len(contents)
	var hdr []byte
	switch {
	case l < 0x80:
		hdr = []byte{identifier, byte(l)}
	case l < 0x100:
		hdr = []byte{identifier, 0x81, byte(l)}
	case l < 0x10000:
		hdr = []byte{identifier, 0x82, byte(l >> 8), byte(l)}
	case l < 0x1000000:
		hdr = []byte{identifier, 0x83, byte(l >> 16), byte(l >> 8), byte(l)}
	default:
		hdr = []byte{identifier, 0x84, byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)}
	}
	return append(hdr, contents...)
}
