package cfdiclient

import (
	"fmt"
	"path"
	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

var internalNSMap = map[string]string{
	"s":   "http://schemas.xmlsoap.org/soap/envelope/",
	"o":   "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
	"u":   "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	"des": "http://DescargaMasivaTerceros.sat.gob.mx",
	"":    "http://www.w3.org/2000/09/xmldsig#",
}

var externalNSMap = map[string]string{
	"":    "http://DescargaMasivaTerceros.sat.gob.mx",
	"s":   "http://schemas.xmlsoap.org/soap/envelope/",
	"u":   "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
	"o":   "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
	"h":   "http://DescargaMasivaTerceros.sat.gob.mx",
	"xsi": "http://www.w3.org/2001/XMLSchema-instance",
	"xsd": "http://www.w3.org/2001/XMLSchema",
}

// loadTemplate reads a bundled XML template into a fresh etree document.
// Whitespace-only text nodes between elements are stripped so the resulting
// tree matches what lxml produces with XMLParser(remove_blank_text=True) —
// a prerequisite for byte-identical canonicalization.
func loadTemplate(name string) (*etree.Document, error) {
	data, err := templatesFS.ReadFile(path.Join("templates", name))
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", name, err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(data); err != nil {
		return nil, fmt.Errorf("parse template %s: %w", name, err)
	}
	stripBlankText(doc.Root())
	return doc, nil
}

// stripBlankText removes whitespace-only CharData children from any element
// that also contains element children. Leaf elements (pure text) are left
// alone so meaningful content is never destroyed.
func stripBlankText(el *etree.Element) {
	hasElements := false
	for _, t := range el.Child {
		if _, ok := t.(*etree.Element); ok {
			hasElements = true
			break
		}
	}
	if hasElements {
		var drop []etree.Token
		for _, t := range el.Child {
			if cd, ok := t.(*etree.CharData); ok && strings.TrimSpace(cd.Data) == "" {
				drop = append(drop, t)
			}
		}
		for _, t := range drop {
			el.RemoveChild(t)
		}
	}
	for _, child := range el.ChildElements() {
		stripBlankText(child)
	}
}

// findElement resolves a python-style prefix path (e.g. "s:Body/des:Foo/Bar")
// against root using nsmap to resolve each step to its namespace URI. An
// unprefixed step uses nsmap[""].
func findElement(root *etree.Element, xpath string, nsmap map[string]string) *etree.Element {
	cur := root
	for _, step := range strings.Split(xpath, "/") {
		if step == "" {
			continue
		}
		prefix, local := splitPrefix(step)
		ns := nsmap[prefix]
		next := childByNS(cur, ns, local)
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

func splitPrefix(step string) (prefix, local string) {
	if i := strings.Index(step, ":"); i >= 0 {
		return step[:i], step[i+1:]
	}
	return "", step
}

func childByNS(parent *etree.Element, ns, local string) *etree.Element {
	for _, child := range parent.ChildElements() {
		if child.Tag == local && child.NamespaceURI() == ns {
			return child
		}
	}
	return nil
}

// setElementText sets the text of the element resolved by xpath against root.
func setElementText(root *etree.Element, xpath string, nsmap map[string]string, text string) error {
	el := findElement(root, xpath, nsmap)
	if el == nil {
		return fmt.Errorf("element not found: %s", xpath)
	}
	el.SetText(text)
	return nil
}

// canonicalizer shared across the package — exclusive C14N 1.0 without
// comments, matching lxml's etree.tostring(method='c14n', exclusive=1).
var c14n = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")

// canonicalize returns the exclusive-C14N serialization of element. Because
// goxmldsig's transform does not walk up to collect ancestor xmlns
// declarations, we first build the parent NS context and detach the element
// with all inherited namespaces attached. Exclusive C14N then drops whichever
// are not visibly utilized — matching lxml's c14n(exclusive=1) on a subtree.
func canonicalize(el *etree.Element) ([]byte, error) {
	ctx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, fmt.Errorf("ns context: %w", err)
	}
	detached, err := etreeutils.NSDetatch(ctx, el)
	if err != nil {
		return nil, fmt.Errorf("ns detach: %w", err)
	}
	return c14n.Canonicalize(detached)
}

// iterByNS walks all descendants of root that match (ns, local).
func iterByNS(root *etree.Element, ns, local string) []*etree.Element {
	var out []*etree.Element
	var walk func(*etree.Element)
	walk = func(e *etree.Element) {
		if e.Tag == local && e.NamespaceURI() == ns {
			out = append(out, e)
		}
		for _, c := range e.ChildElements() {
			walk(c)
		}
	}
	walk(root)
	return out
}
