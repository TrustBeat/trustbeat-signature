package extract

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/beevik/etree"

	"github.com/TrustBeat/trustbeat-signature/internal/cms"
)

const (
	mimeASiCE = "application/vnd.etsi.asic-e+zip"
	mimeASiCS = "application/vnd.etsi.asic-s+zip"
	// maxEntry bounds one ZIP entry so a hostile container cannot exhaust memory.
	maxEntry = 2 << 30
)

// extractASiC handles ASiC-E and ASiC-S containers with XAdES or CAdES signatures. The data
// objects stay on the customer's machine; only their names and digests are reported.
func extractASiC(in Input, sub *Submission) error {
	zr, err := zip.NewReader(bytes.NewReader(in.Bytes), int64(len(in.Bytes)))
	if err != nil {
		return malformed(err, "ZIP")
	}
	entries := map[string][]byte{}
	var names []string
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if _, dup := entries[f.Name]; dup {
			return refuse(ReasonMalformed, "ZIP entry %q appears twice", f.Name)
		}
		if f.UncompressedSize64 > maxEntry {
			return refuse(ReasonUnsupported, "ZIP entry %q is larger than 2 GiB", f.Name)
		}
		rc, err := f.Open()
		if err != nil {
			return malformed(err, "ZIP entry "+f.Name)
		}
		b, err := io.ReadAll(io.LimitReader(rc, maxEntry+1))
		rc.Close()
		if err != nil {
			return malformed(err, "ZIP entry "+f.Name)
		}
		entries[f.Name] = b
		names = append(names, f.Name)
	}
	sort.Strings(names)
	data := map[string][]byte{}
	for _, n := range names {
		if n != "mimetype" && !strings.HasPrefix(n, "META-INF/") {
			data[n] = entries[n]
			sub.DataObjects = append(sub.DataObjects, FileInfo{Name: n, SizeBytes: int64(len(entries[n])), Digests: fileDigests(entries[n])})
		}
	}
	// The mimetype entry is found by name: it is not always first (fixture asice-xades-multifile).
	switch mt := strings.TrimSpace(string(entries["mimetype"])); {
	case mt == mimeASiCE:
		sub.Container.Format = FormatASiCE
	case mt == mimeASiCS:
		sub.Container.Format = FormatASiCS
	case mt == "" && len(data) == 1:
		sub.Container.Format = FormatASiCS
	case mt == "":
		sub.Container.Format = FormatASiCE
	default:
		return refuse(ReasonUnsupported, "ZIP with mimetype %q is not an ASiC container", mt)
	}
	if len(data) == 0 {
		return refuse(ReasonMalformed, "ASiC container without data objects")
	}
	if len(in.Data) > 0 {
		return refuse(ReasonUnsupported, "--data is not used with ASiC containers: the data is inside")
	}

	covered := map[string]bool{}
	for _, n := range names {
		base := strings.TrimPrefix(n, "META-INF/")
		if base == n {
			continue
		}
		lower := strings.ToLower(base)
		var err error
		switch {
		case strings.Contains(lower, "signatures") && strings.HasSuffix(lower, ".xml"):
			var sigs []Signature
			var used map[string]bool
			if sigs, used, err = xmlSignatures(entries[n], n, data); err == nil {
				sub.Signatures = append(sub.Signatures, sigs...)
				for k := range used {
					covered[k] = true
				}
			}
		case strings.Contains(lower, "signature") && strings.HasSuffix(lower, ".p7s"):
			err = asicCAdES(sub, n, entries, data, covered)
		case strings.HasSuffix(lower, ".tst"):
			err = asicTimestamp(sub, n, entries, data)
		case strings.HasSuffix(lower, ".ers"):
			sub.Notes = append(sub.Notes, fmt.Sprintf("%s (evidence record) is not preserved", n))
		}
		if err != nil {
			return err
		}
	}
	for _, n := range names {
		if _, ok := data[n]; ok && !covered[n] && len(sub.Signatures) > 0 {
			sub.Notes = append(sub.Notes, fmt.Sprintf("data object %s is not covered by any signature", n))
		}
	}
	return nil
}

// asicCAdES: ASiC-E CAdES signs an ASiCManifest (whose entries are then checked) — kept as a
// separate entry, or encapsulated in the signature itself; ASiC-S CAdES signs the single data
// object.
func asicCAdES(sub *Submission, name string, entries, data map[string][]byte, covered map[string]bool) error {
	sd, err := cms.Parse(entries[name])
	if err != nil {
		return malformed(err, name)
	}
	sig := Signature{Format: FormatCAdES, Source: name, SignatureB64: b64(sd.Raw)}
	mName, mBytes, m, err := manifestFor(name, entries, "ASiCManifest")
	if err != nil {
		return err
	}
	if sd.EContent != nil {
		// Only a manifest may be encapsulated: data objects must stay out of the submission.
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(sd.EContent); err != nil || doc.Root() == nil || doc.Root().Tag != "ASiCManifest" {
			return refuse(ReasonUnsupported, "%s encapsulates content other than an ASiCManifest", name)
		}
		if m == nil || !bytes.Equal(mBytes, sd.EContent) {
			mName, mBytes, m = name+"#eContent", sd.EContent, doc.Root()
		}
	}
	if m != nil {
		if sig.Binding, err = cmsBindings(sd, "manifest", mName, mBytes); err != nil {
			return err
		}
		entryBindings, err := manifestEntries(m, mName, entries)
		if err != nil {
			return err
		}
		for _, b := range entryBindings {
			covered[b.Target] = true
		}
		sig.Binding = append(sig.Binding, entryBindings...)
		sig.ManifestB64 = b64(mBytes)
	} else {
		if len(data) != 1 {
			return refuse(ReasonMalformed, "%s: no ASiCManifest references it and the container holds %d data objects", name, len(data))
		}
		for dn, db := range data {
			if sig.Binding, err = cmsBindings(sd, "content", dn, db); err != nil {
				return err
			}
			covered[dn] = true
		}
	}
	sub.Signatures = append(sub.Signatures, sig)
	return nil
}

// asicTimestamp: an ASiC-E timestamp covers an ASiCArchiveManifest (an archive timestamp,
// whose entries include signatures and earlier manifests); an ASiC-S one covers the data object.
func asicTimestamp(sub *Submission, name string, entries, data map[string][]byte) error {
	sd, err := cms.Parse(entries[name])
	if err != nil {
		return malformed(err, name)
	}
	mi, err := sd.TimestampImprint()
	if err != nil {
		return malformed(err, name)
	}
	ts := Timestamp{Source: name, TokenB64: b64(sd.Raw)}
	check := func(kind, target string, b []byte) error {
		d, err := digestOID(mi.Algorithm, b)
		if err != nil {
			return err
		}
		if !bytes.Equal(d, mi.Digest) {
			return refuse(ReasonDigestMismatch, "%s does not cover %s", name, target)
		}
		ts.Binding = append(ts.Binding, Binding{Kind: kind, Target: target, Alg: mi.Algorithm.String(), Digest: hexs(mi.Digest), Checked: true})
		return nil
	}
	mName, mBytes, m, err := manifestFor(name, entries, "ASiCArchiveManifest")
	if err != nil {
		return err
	}
	if m == nil {
		mName, mBytes, m, err = manifestFor(name, entries, "ASiCManifest")
		if err != nil {
			return err
		}
	}
	switch {
	case m != nil:
		ts.Kind = "asic-manifest-timestamp"
		if err := check("manifest", mName, mBytes); err != nil {
			return err
		}
		eb, err := manifestEntries(m, mName, entries)
		if err != nil {
			return err
		}
		ts.Binding = append(ts.Binding, eb...)
		ts.ManifestB64 = b64(mBytes)
	case len(data) == 1:
		ts.Kind = "asic-container-timestamp"
		for dn, db := range data {
			if err := check("content", dn, db); err != nil {
				return err
			}
		}
	default:
		return refuse(ReasonMalformed, "%s: no manifest references it", name)
	}
	sub.Timestamps = append(sub.Timestamps, ts)
	return nil
}

// manifestFor finds the META-INF/<prefix>*.xml whose SigReference points at sigName.
func manifestFor(sigName string, entries map[string][]byte, prefix string) (string, []byte, *etree.Element, error) {
	var names []string
	for n := range entries {
		if strings.HasPrefix(n, "META-INF/"+prefix) && strings.HasSuffix(n, ".xml") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(entries[n]); err != nil || doc.Root() == nil {
			return "", nil, nil, refuse(ReasonMalformed, "%s does not parse", n)
		}
		for _, c := range doc.Root().ChildElements() {
			if c.Tag == "SigReference" && unescape(c.SelectAttrValue("URI", "")) == sigName {
				return n, entries[n], doc.Root(), nil
			}
		}
	}
	return "", nil, nil, nil
}

// manifestEntries checks every DataObjectReference of an ASiC manifest against the container.
func manifestEntries(m *etree.Element, mName string, entries map[string][]byte) ([]Binding, error) {
	var out []Binding
	for _, c := range m.ChildElements() {
		if c.Tag != "DataObjectReference" {
			continue
		}
		target := unescape(c.SelectAttrValue("URI", ""))
		var alg, val string
		for _, d := range c.ChildElements() {
			switch d.Tag {
			case "DigestMethod":
				alg = d.SelectAttrValue("Algorithm", "")
			case "DigestValue":
				val = strings.Join(strings.Fields(d.Text()), "")
			}
		}
		want, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, refuse(ReasonMalformed, "%s: digest of %s is not base64", mName, target)
		}
		b, ok := entries[target]
		if !ok {
			return nil, refuse(ReasonMissingData, "%s lists %s, which is not in the container", mName, target)
		}
		got, err := digestURI(alg, b)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, want) {
			return nil, refuse(ReasonDigestMismatch, "%s: %s does not match its digest", mName, target)
		}
		out = append(out, Binding{Kind: "manifest-entry", Target: target, Alg: alg, Digest: hexs(want), Checked: true})
	}
	return out, nil
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		s = u
	}
	return strings.TrimPrefix(s, "./")
}

func sortFiles(f []FileInfo) { sort.Slice(f, func(i, j int) bool { return f[i].Name < f[j].Name }) }
