package extract

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"golang.org/x/text/encoding/charmap"
)

const (
	dsNS     = "http://www.w3.org/2000/09/xmldsig#"
	xadesTyp = "http://uri.etsi.org/01903#SignedProperties"

	trEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	trBase64    = "http://www.w3.org/2000/09/xmldsig#base64"
	trXPath     = "http://www.w3.org/TR/1999/REC-xpath-19991116"
	trXPath2    = "http://www.w3.org/2002/06/xmldsig-filter2"

	c14n10   = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	c14n10C  = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	c14n11   = "http://www.w3.org/2006/12/xml-c14n11"
	c14n11C  = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
	excC14n  = "http://www.w3.org/2001/10/xml-exc-c14n#"
	excC14nC = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
)

// extractXMLFile handles a standalone XML file with one or more XAdES signatures (enveloped,
// enveloping or detached); detached references resolve against the --data files.
func extractXMLFile(in Input, sub *Submission) error {
	sigs, used, err := xmlSignatures(in.Bytes, sub.Container.Name, in.Data)
	if err != nil {
		return err
	}
	for name := range in.Data {
		if !used[name] {
			return refuse(ReasonUnsupported, "--data %s is not referenced by any signature", name)
		}
		sub.DataObjects = append(sub.DataObjects, FileInfo{Name: name, SizeBytes: int64(len(in.Data[name])), Digests: fileDigests(in.Data[name])})
	}
	sortFiles(sub.DataObjects)
	sub.Signatures = append(sub.Signatures, sigs...)
	return nil
}

// xmlDoc is one XML file prepared for signature work.
type xmlDoc struct {
	text    []byte // UTF-8 text with an UTF-8 declaration (the original bytes unless re-encoded)
	decl    []byte // the XML declaration as it appears in text, or nil
	recoded bool
	doc     *etree.Document
	ids     map[string]*etree.Element
	dupIDs  map[string]bool
}

var reEncoding = regexp.MustCompile(`(?i)^(<\?xml[^>]*?encoding\s*=\s*["'])([A-Za-z0-9._-]+)(["'][^>]*\?>)`)
var reDecl = regexp.MustCompile(`^<\?xml[^>]*\?>`)

// loadXML normalises the encoding to UTF-8 (only ISO-8859-1 / Windows-1252 are converted), refuses
// DTDs (entity expansion would make a cut signature differ from the signed one), parses, and
// indexes Id attributes. A duplicated Id is refused when a reference points at it — the basis
// of signature-wrapping attacks.
func loadXML(raw []byte) (*xmlDoc, error) {
	x := &xmlDoc{text: bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))}
	if m := reEncoding.FindSubmatchIndex(x.text); m != nil {
		enc := strings.ToLower(string(x.text[m[4]:m[5]]))
		switch enc {
		case "utf-8", "utf8":
		case "iso-8859-1", "latin1", "iso8859-1", "windows-1252", "cp1252":
			cm := charmap.ISO8859_1
			if strings.Contains(enc, "1252") {
				cm = charmap.Windows1252
			}
			u, err := cm.NewDecoder().Bytes(x.text)
			if err != nil {
				return nil, malformed(err, "XML encoding")
			}
			m2 := reEncoding.FindSubmatchIndex(u)
			x.text = append(append(append([]byte{}, u[:m2[4]]...), "UTF-8"...), u[m2[5]:]...)
			x.recoded = true
		default:
			return nil, refuse(ReasonUnsupported, "XML encoding %q", enc)
		}
	}
	if d := reDecl.Find(x.text); d != nil {
		x.decl = d
	}
	if bytes.Contains(x.text, []byte("<!DOCTYPE")) {
		return nil, refuse(ReasonUnsupported, "XML with a DOCTYPE")
	}
	x.doc = etree.NewDocument()
	if err := x.doc.ReadFromBytes(x.text); err != nil {
		return nil, malformed(err, "XML")
	}
	if x.doc.Root() == nil {
		return nil, refuse(ReasonMalformed, "XML has no root element")
	}
	x.ids, x.dupIDs = map[string]*etree.Element{}, map[string]bool{}
	walk(x.doc.Root(), func(e *etree.Element) {
		for _, a := range e.Attr {
			if a.Space == "" && (a.Key == "Id" || a.Key == "ID" || a.Key == "id") {
				if _, ok := x.ids[a.Value]; ok {
					x.dupIDs[a.Value] = true
				}
				x.ids[a.Value] = e
			}
		}
	})
	return x, nil
}

func walk(e *etree.Element, f func(*etree.Element)) {
	f(e)
	for _, c := range e.ChildElements() {
		walk(c, f)
	}
}

func isDS(e *etree.Element, tag string) bool {
	return e != nil && e.Tag == tag && e.NamespaceURI() == dsNS
}

func dsChild(e *etree.Element, tag string) *etree.Element {
	for _, c := range e.ChildElements() {
		if isDS(c, tag) {
			return c
		}
	}
	return nil
}

func dsChildren(e *etree.Element, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range e.ChildElements() {
		if isDS(c, tag) {
			out = append(out, c)
		}
	}
	return out
}

// topSignatures are ds:Signature elements not nested in another one (counter-signatures stay
// inside their parent).
func topSignatures(root *etree.Element) []*etree.Element {
	var out []*etree.Element
	var rec func(e *etree.Element)
	rec = func(e *etree.Element) {
		if isDS(e, "Signature") {
			out = append(out, e)
			return
		}
		for _, c := range e.ChildElements() {
			rec(c)
		}
	}
	rec(root)
	return out
}

// span is a byte range [start, end) in xmlDoc.text.
type span struct{ start, end int64 }

// sigSpans returns, in document order, each top-level ds:Signature's span and the spans of its
// direct ds:Object children, found with encoding/xml's byte offsets.
func sigSpans(text []byte) ([]span, [][]span, error) {
	d := xml.NewDecoder(bytes.NewReader(text))
	var sigs []span
	var objs [][]span
	depth, sigDepth := 0, -1
	var objStart int64 = -1
	for {
		off := d.InputOffset()
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, malformed(err, "XML")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if t.Name.Space == dsNS && t.Name.Local == "Signature" && sigDepth < 0 {
				sigDepth = depth
				sigs = append(sigs, span{start: off})
				objs = append(objs, nil)
			} else if sigDepth > 0 && depth == sigDepth+1 && t.Name.Space == dsNS && t.Name.Local == "Object" {
				objStart = off
			}
		case xml.EndElement:
			end := d.InputOffset()
			if sigDepth > 0 && depth == sigDepth+1 && objStart >= 0 && t.Name.Space == dsNS && t.Name.Local == "Object" {
				objs[len(objs)-1] = append(objs[len(objs)-1], span{objStart, end})
				objStart = -1
			}
			if depth == sigDepth {
				sigs[len(sigs)-1].end = end
				sigDepth = -1
			}
			depth--
		}
	}
	return sigs, objs, nil
}

// xmlSignatures processes every top-level signature in raw. used reports which data files the
// references resolved to.
func xmlSignatures(raw []byte, source string, data map[string][]byte) ([]Signature, map[string]bool, error) {
	x, err := loadXML(raw)
	if err != nil {
		return nil, nil, err
	}
	tops := topSignatures(x.doc.Root())
	spans, objSpans, err := sigSpans(x.text)
	if err != nil {
		return nil, nil, err
	}
	if len(spans) != len(tops) {
		return nil, nil, refuse(ReasonMalformed, "XML signatures: %d by element, %d by offset", len(tops), len(spans))
	}
	used := map[string]bool{}
	var out []Signature
	for i, sigEl := range tops {
		s, err := xmlSignature(x, sigEl, spans[i], objSpans[i], data, used)
		if err != nil {
			return nil, nil, err
		}
		s.Source = source
		out = append(out, s)
	}
	return out, used, nil
}

func xmlSignature(x *xmlDoc, sigEl *etree.Element, sp span, objs []span, data map[string][]byte, used map[string]bool) (Signature, error) {
	sig := Signature{Format: FormatXAdES, ID: sigEl.SelectAttrValue("Id", "")}
	label := sig.ID
	if label == "" {
		label = "(no Id)"
	}
	si := dsChild(sigEl, "SignedInfo")
	if si == nil {
		return sig, refuse(ReasonMalformed, "signature %s has no SignedInfo", label)
	}
	siC14N, err := canonicalSignedInfo(si)
	if err != nil {
		return sig, err
	}
	sig.SignedInfoC14NSHA256 = sum(sha256.New, siC14N)

	inside := map[int]bool{} // references whose target lies inside the signature
	refs := dsChildren(si, "Reference")
	for i, ref := range refs {
		b, internal, err := checkReference(x, sigEl, ref, data, used)
		if err != nil {
			return sig, fmt.Errorf("signature %s: %w", label, err)
		}
		inside[i] = internal
		sig.Binding = append(sig.Binding, b)
	}

	cut, derived, err := cutSignature(x, sigEl, sp, objs)
	if err != nil {
		return sig, err
	}
	// Self-check: the cut-out signature must give the same canonical SignedInfo and the same
	// digests for the references it still contains (SignedProperties, KeyInfo, …). Otherwise
	// the server could not verify what the customer signed.
	cx, err := loadXML(cut)
	if err != nil {
		return sig, fmt.Errorf("signature %s: cut-out copy does not parse: %w", label, err)
	}
	cSig := topSignatures(cx.doc.Root())
	if len(cSig) != 1 {
		return sig, refuse(ReasonMalformed, "signature %s: cut-out copy has %d signatures", label, len(cSig))
	}
	cSI := dsChild(cSig[0], "SignedInfo")
	c2, err := canonicalSignedInfo(cSI)
	if err != nil || !bytes.Equal(c2, siC14N) {
		return sig, refuse(ReasonUnsupported, "signature %s cannot be cut out of the document without changing its SignedInfo", label)
	}
	for i, ref := range dsChildren(cSI, "Reference") {
		if !inside[i] {
			continue
		}
		b, _, err := checkReference(cx, cSig[0], ref, nil, map[string]bool{})
		if err != nil || b.Digest != sig.Binding[i].Digest {
			return sig, refuse(ReasonUnsupported, "signature %s: reference %q changes when the signature is cut out", label, ref.SelectAttrValue("URI", ""))
		}
	}
	if x.recoded {
		derived = append(derived, "re-encoded-utf8")
	}
	sig.SignatureB64 = b64(cut)
	sig.Derived = derived
	return sig, nil
}

func canonicalizationOf(e *etree.Element) (string, string) {
	pl := ""
	for _, c := range e.ChildElements() {
		if c.Tag == "InclusiveNamespaces" {
			pl = c.SelectAttrValue("PrefixList", "")
		}
	}
	return e.SelectAttrValue("Algorithm", ""), pl
}

func canonicalizer(alg, prefixList string, comments bool) (dsig.Canonicalizer, error) {
	switch alg {
	case c14n10, c14n10C:
		if comments && alg == c14n10C {
			return dsig.MakeC14N10WithCommentsCanonicalizer(), nil
		}
		return dsig.MakeC14N10RecCanonicalizer(), nil
	case c14n11, c14n11C:
		if comments && alg == c14n11C {
			return dsig.MakeC14N11WithCommentsCanonicalizer(), nil
		}
		return dsig.MakeC14N11Canonicalizer(), nil
	case excC14n, excC14nC:
		if comments && alg == excC14nC {
			return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList(prefixList), nil
		}
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(prefixList), nil
	}
	return nil, refuse(ReasonUnsupported, "canonicalization %s", alg)
}

func isC14N(alg string) bool {
	switch alg {
	case c14n10, c14n10C, c14n11, c14n11C, excC14n, excC14nC:
		return true
	}
	return false
}

func inclusive(alg string) bool { return isC14N(alg) && alg != excC14n && alg != excC14nC }

// canonicalSignedInfo canonicalises SignedInfo in its namespace context (SignedInfo is an
// explicit node-set, so a WithComments method keeps comments).
func canonicalSignedInfo(si *etree.Element) ([]byte, error) {
	cm := dsChild(si, "CanonicalizationMethod")
	if cm == nil {
		return nil, refuse(ReasonMalformed, "SignedInfo has no CanonicalizationMethod")
	}
	alg, pl := canonicalizationOf(cm)
	c, err := canonicalizer(alg, pl, true)
	if err != nil {
		return nil, err
	}
	if inclusive(alg) && inheritsXMLAttrs(si) {
		return nil, refuse(ReasonUnsupported, "inclusive canonicalization with inherited xml:* attributes")
	}
	d, err := detach(si)
	if err != nil {
		return nil, malformed(err, "namespace context")
	}
	return c.Canonicalize(d)
}

// inheritsXMLAttrs reports xml:lang / xml:space / xml:base / xml:id on an ancestor. Inclusive
// canonicalization would copy them onto the apex; goxmldsig does not, so such documents are
// refused rather than canonicalised differently from Santuario.
func inheritsXMLAttrs(e *etree.Element) bool {
	for p := e.Parent(); p != nil && p.Tag != ""; p = p.Parent() {
		for _, a := range p.Attr {
			if a.Space == "xml" {
				return true
			}
		}
	}
	return false
}

// detach copies e with the namespace declarations it inherits.
func detach(e *etree.Element) (*etree.Element, error) {
	var chain []*etree.Element
	for p := e.Parent(); p != nil && p.Tag != ""; p = p.Parent() {
		chain = append([]*etree.Element{p}, chain...)
	}
	ctx := etreeutils.NewDefaultNSContext()
	for _, a := range chain {
		var err error
		if ctx, err = ctx.SubContext(a); err != nil {
			return nil, err
		}
	}
	return etreeutils.NSDetatch(ctx, e)
}

func contains(ancestor, e *etree.Element) bool {
	for p := e; p != nil; p = p.Parent() {
		if p == ancestor {
			return true
		}
	}
	return false
}

// pathTo is the child-index path from root to target, or nil.
func pathTo(root, target *etree.Element) []int {
	var rev []int
	for e := target; e != root; e = e.Parent() {
		p := e.Parent()
		if p == nil {
			return nil
		}
		idx := -1
		for i, c := range p.ChildElements() {
			if c == e {
				idx = i
			}
		}
		rev = append(rev, idx)
	}
	out := make([]int, len(rev))
	for i, v := range rev {
		out[len(rev)-1-i] = v
	}
	return out
}

func at(root *etree.Element, p []int) *etree.Element {
	for _, i := range p {
		root = root.ChildElements()[i]
	}
	return root
}

// stringValue is the XPath string-value of an element: its descendant text in document order.
func stringValue(e *etree.Element) string {
	var b strings.Builder
	var rec func(e *etree.Element)
	rec = func(e *etree.Element) {
		for _, t := range e.Child {
			switch v := t.(type) {
			case *etree.CharData:
				b.WriteString(v.Data)
			case *etree.Element:
				rec(v)
			}
		}
	}
	rec(e)
	return b.String()
}

// data in a transform chain: a node-set (an element copy, with or without comments) or octets.
type refData struct {
	node     *etree.Element
	comments bool
	octets   []byte
	isOctets bool
}

// checkReference dereferences a ds:Reference, applies its transforms, and compares the digest.
// internal reports whether the target is inside the signature element itself.
func checkReference(x *xmlDoc, sigEl, ref *etree.Element, data map[string][]byte, used map[string]bool) (b Binding, internal bool, err error) {
	uri, hasURI := "", false
	for _, a := range ref.Attr {
		if a.Space == "" && a.Key == "URI" {
			uri, hasURI = a.Value, true
		}
	}
	b = Binding{Kind: "reference", Type: ref.SelectAttrValue("Type", ""), Checked: true}
	if hasURI {
		b.URI = &uri
	}
	dm, dv := dsChild(ref, "DigestMethod"), dsChild(ref, "DigestValue")
	if dm == nil || dv == nil {
		return b, false, refuse(ReasonMalformed, "reference %q without DigestMethod/DigestValue", uri)
	}
	b.Alg = dm.SelectAttrValue("Algorithm", "")
	want, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(dv.Text()), ""))
	if err != nil {
		return b, false, refuse(ReasonDigestMismatch, "reference %q: DigestValue is not base64", uri)
	}
	b.Digest = hexs(want)
	var transforms []*etree.Element
	if t := dsChild(ref, "Transforms"); t != nil {
		transforms = dsChildren(t, "Transform")
	}
	for _, t := range transforms {
		b.Transforms = append(b.Transforms, t.SelectAttrValue("Algorithm", ""))
	}

	// Dereference.
	var cur refData
	var sigPath []int // path from the node-set root to sigEl, for the enveloped transform
	switch {
	case !hasURI:
		return b, false, refuse(ReasonUnsupported, "reference without URI")
	case uri == "" || uri == "#xpointer(/)":
		root := x.doc.Root()
		cur = refData{node: root.Copy(), comments: uri != ""}
		sigPath = pathTo(root, sigEl)
	case strings.HasPrefix(uri, "#"):
		id := strings.TrimPrefix(uri, "#")
		comments := false
		if strings.HasPrefix(id, "xpointer(id(") && strings.HasSuffix(id, "))") {
			id = strings.Trim(strings.TrimSuffix(strings.TrimPrefix(id, "xpointer(id("), "))"), `'"`)
			comments = true
		} else if strings.HasPrefix(id, "xpointer(") {
			return b, false, refuse(ReasonUnsupported, "XPointer %s", uri)
		}
		if x.dupIDs[id] {
			return b, false, refuse(ReasonMalformed, "reference %q: the Id is used by more than one element", uri)
		}
		el, ok := x.ids[id]
		if !ok {
			return b, false, refuse(ReasonMissingData, "reference %q: no element with that Id", uri)
		}
		// Inside the signature and kept by the cut (content Objects are removed from it).
		internal = contains(sigEl, el) && !inContentObject(x, sigEl, el)
		if !internal && contains(el, sigEl) {
			sigPath = pathTo(el, sigEl)
		}
		for _, t := range b.Transforms {
			if inclusive(t) && inheritsXMLAttrs(el) {
				return b, false, refuse(ReasonUnsupported, "inclusive canonicalization with inherited xml:* attributes")
			}
		}
		d, err := detach(el)
		if err != nil {
			return b, false, malformed(err, "namespace context")
		}
		cur = refData{node: d, comments: comments}
	default:
		name, err := url.PathUnescape(uri)
		if err != nil {
			name = uri
		}
		name = strings.TrimPrefix(name, "./")
		v, ok := data[name]
		if !ok {
			if v, ok = data[path.Base(name)]; ok {
				name = path.Base(name)
			}
		}
		if !ok {
			return b, false, refuse(ReasonMissingData, "reference %q: the signed file is not available (give it with --data)", uri)
		}
		used[name] = true
		b.Target = name
		cur = refData{octets: v, isOctets: true}
	}

	for _, t := range transforms {
		alg := t.SelectAttrValue("Algorithm", "")
		switch {
		case alg == trEnveloped:
			if !cur.isOctets && sigPath != nil {
				removeAt(cur.node, sigPath)
				sigPath = nil
			}
		case alg == trXPath:
			if cur.isOctets {
				return b, false, refuse(ReasonUnsupported, "XPath transform on octets")
			}
			if err := xpathNotSignature(t, cur.node); err != nil {
				return b, false, err
			}
			sigPath = nil
		case alg == trXPath2:
			if cur.isOctets {
				return b, false, refuse(ReasonUnsupported, "XPath Filter 2.0 on octets")
			}
			removedOwn, err := xpathFilter2(t, cur.node, sigPath)
			if err != nil {
				return b, false, err
			}
			if removedOwn {
				sigPath = nil
			}
		case alg == trBase64:
			text := string(cur.octets)
			if !cur.isOctets {
				text = stringValue(cur.node)
			}
			dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text), ""))
			if err != nil {
				return b, false, refuse(ReasonMalformed, "reference %q: base64 transform input is not base64", uri)
			}
			cur = refData{octets: dec, isOctets: true}
		case isC14N(alg):
			_, pl := canonicalizationOf(t)
			node, comments := cur.node, cur.comments
			if cur.isOctets {
				d := etree.NewDocument()
				if err := d.ReadFromBytes(cur.octets); err != nil || d.Root() == nil {
					return b, false, refuse(ReasonUnsupported, "reference %q: canonicalization of data that is not XML", uri)
				}
				node, comments = d.Root(), true
			}
			c, err := canonicalizer(alg, pl, comments)
			if err != nil {
				return b, false, err
			}
			o, err := c.Canonicalize(node)
			if err != nil {
				return b, false, malformed(err, "canonicalization")
			}
			cur = refData{octets: o, isOctets: true}
		default:
			return b, false, refuse(ReasonUnsupported, "reference %q: transform %s", uri, alg)
		}
	}
	if !cur.isOctets {
		// Node-set to octets: inclusive C14N 1.0 (XML-DSig §4.4.3.2).
		alg := c14n10
		if cur.comments {
			alg = c14n10C
		}
		c, _ := canonicalizer(alg, "", cur.comments)
		o, err := c.Canonicalize(cur.node)
		if err != nil {
			return b, false, malformed(err, "canonicalization")
		}
		cur = refData{octets: o, isOctets: true}
	}
	got, err := digestURI(b.Alg, cur.octets)
	if err != nil {
		return b, false, err
	}
	if !bytes.Equal(got, want) {
		return b, internal, refuse(ReasonDigestMismatch, "reference %q does not match its data", uri)
	}
	return b, internal, nil
}

func removeAt(root *etree.Element, p []int) {
	if len(p) == 0 {
		return
	}
	e := at(root, p)
	e.Parent().RemoveChild(e)
}

func removeAll(root *etree.Element, match func(*etree.Element) bool) {
	for _, c := range root.ChildElements() {
		if match(c) {
			root.RemoveChild(c)
		} else {
			removeAll(c, match)
		}
	}
}

var spaces = regexp.MustCompile(`\s+`)

// xpathNotSignature supports the one XPath 1.0 expression used in practice,
// not(ancestor-or-self::P:Signature) with P bound to XML-DSig: remove every signature.
func xpathNotSignature(t, node *etree.Element) error {
	xp := firstChild(t, "XPath")
	if xp == nil {
		return refuse(ReasonMalformed, "XPath transform without XPath")
	}
	expr := spaces.ReplaceAllString(xp.Text(), "")
	m := regexp.MustCompile(`^not\(ancestor-or-self::([A-Za-z_][\w.-]*):Signature\)$`).FindStringSubmatch(expr)
	if m == nil || nsOf(xp, m[1]) != dsNS {
		return refuse(ReasonUnsupported, "XPath expression %q", xp.Text())
	}
	removeAll(node, func(e *etree.Element) bool { return isDS(e, "Signature") })
	return nil
}

// xpathFilter2 supports a single subtract filter that removes signatures: by qualified name
// (/descendant::*[name()='P:Signature']), by namespace (//P:Signature, /descendant::P:Signature)
// or only the enclosing one (here()/ancestor::P:Signature[1]).
func xpathFilter2(t, node *etree.Element, sigPath []int) (bool, error) {
	var xps []*etree.Element
	for _, c := range t.ChildElements() {
		if c.Tag == "XPath" && c.NamespaceURI() == trXPath2 {
			xps = append(xps, c)
		}
	}
	if len(xps) != 1 || xps[0].SelectAttrValue("Filter", "") != "subtract" {
		return false, refuse(ReasonUnsupported, "XPath Filter 2.0 other than one subtract filter")
	}
	xp := xps[0]
	expr := spaces.ReplaceAllString(xp.Text(), "")
	if m := regexp.MustCompile(`^/descendant::\*\[name\(\)=['"]([A-Za-z_][\w.-]*:)?Signature['"]\]$`).FindStringSubmatch(expr); m != nil {
		prefix := strings.TrimSuffix(m[1], ":")
		removeAll(node, func(e *etree.Element) bool { return e.Space == prefix && e.Tag == "Signature" })
		return true, nil
	}
	if m := regexp.MustCompile(`^(?://|/descendant::)([A-Za-z_][\w.-]*):Signature$`).FindStringSubmatch(expr); m != nil && nsOf(xp, m[1]) == dsNS {
		removeAll(node, func(e *etree.Element) bool { return isDS(e, "Signature") })
		return true, nil
	}
	if m := regexp.MustCompile(`^here\(\)/ancestor::([A-Za-z_][\w.-]*):Signature\[1\]$`).FindStringSubmatch(expr); m != nil && nsOf(xp, m[1]) == dsNS {
		removeAt(node, sigPath)
		return true, nil
	}
	return false, refuse(ReasonUnsupported, "XPath Filter 2.0 expression %q", xp.Text())
}

func firstChild(e *etree.Element, tag string) *etree.Element {
	for _, c := range e.ChildElements() {
		if c.Tag == tag {
			return c
		}
	}
	return nil
}

// nsOf resolves prefix in e's scope.
func nsOf(e *etree.Element, prefix string) string {
	for p := e; p != nil && p.Tag != ""; p = p.Parent() {
		for _, a := range p.Attr {
			if a.Space == "xmlns" && a.Key == prefix {
				return a.Value
			}
		}
	}
	return ""
}

// cutSignature returns the signature's original bytes with (1) the namespace declarations it
// inherits added to its start tag, (2) content ds:Objects (enveloping) removed, and (3) the
// document's XML declaration in front. Nothing else is touched.
func cutSignature(x *xmlDoc, sigEl *etree.Element, sp span, objs []span) ([]byte, []string, error) {
	var derived []string
	text := x.text
	var body []byte
	pos := sp.start
	for _, o := range objs {
		obj := elementAtOffset(sigEl, o, objs)
		if obj == nil || !isContentObject(x, sigEl, obj) {
			continue
		}
		body = append(body, text[pos:o.start]...)
		pos = o.end
		if len(derived) == 0 {
			derived = append(derived, "content-detached")
		}
	}
	body = append(body, text[pos:sp.end]...)

	// Inherited namespace declarations, nearest ancestor first; skip those the element redeclares.
	own := map[string]bool{}
	for _, a := range sigEl.Attr {
		if a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns") {
			own[a.FullKey()] = true
		}
	}
	var add []string
	for p := sigEl.Parent(); p != nil && p.Tag != ""; p = p.Parent() {
		for _, a := range p.Attr {
			if (a.Space == "xmlns" || (a.Space == "" && a.Key == "xmlns")) && !own[a.FullKey()] {
				own[a.FullKey()] = true
				add = append(add, fmt.Sprintf(` %s="%s"`, a.FullKey(), escapeAttr(a.Value)))
			}
		}
	}
	if len(add) > 0 {
		i := bytes.IndexAny(body, " \t\r\n/>")
		if i < 0 {
			return nil, nil, errors.New("cut signature: no start tag")
		}
		body = append(append(append([]byte{}, body[:i]...), strings.Join(add, "")...), body[i:]...)
		derived = append(derived, "namespace-context")
	}
	out := body
	if x.decl != nil {
		out = append(append(append([]byte{}, x.decl...), '\n'), body...)
	}
	return out, derived, nil
}

// elementAtOffset maps an Object span to its etree element by position among the ds:Object
// children (both lists are in document order).
func elementAtOffset(sigEl *etree.Element, o span, objs []span) *etree.Element {
	els := dsChildren(sigEl, "Object")
	if len(els) != len(objs) {
		return nil
	}
	for i, s := range objs {
		if s == o {
			return els[i]
		}
	}
	return nil
}

// isContentObject: a ds:Object holding the signed document of an enveloping signature (the
// signature is the document root), not signature metadata (XAdES QualifyingProperties,
// ds:Manifest, ds:SignatureProperties). An enveloped signature's document lies outside it, so
// nothing inside it is removed (fixture xades-enveloped-inclusive-inherited-ns keeps its
// SignatureCreationSystemInfo object).
func isContentObject(x *xmlDoc, sigEl, obj *etree.Element) bool {
	if sigEl != x.doc.Root() {
		return false
	}
	meta := false
	walk(obj, func(e *etree.Element) {
		if e.Tag == "QualifyingProperties" || isDS(e, "Manifest") || isDS(e, "SignatureProperties") {
			meta = true
		}
	})
	return !meta
}

func inContentObject(x *xmlDoc, sigEl, el *etree.Element) bool {
	for p := el; p != nil && p != sigEl; p = p.Parent() {
		if isDS(p, "Object") && p.Parent() == sigEl && isContentObject(x, sigEl, p) {
			return true
		}
	}
	return false
}

func escapeAttr(s string) string {
	r := strings.NewReplacer(`&`, "&amp;", `<`, "&lt;", `"`, "&quot;")
	return r.Replace(s)
}
