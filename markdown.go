package main

import (
	"bytes"
	"errors"
	stdhtml "html"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"
	"golang.org/x/net/html"
)

const (
	maxMarkdownInput  = 1 << 20
	maxMarkdownOutput = 4 << 20
	maxMarkdownNodes  = 50_000
	maxMarkdownDepth  = 64
)

var markdownEngine = goldmark.New(goldmark.WithExtensions(extension.GFM))

// renderMarkdown accepts only a bounded UTF-8 source and emits a deliberately
// narrow HTML subset. goldmark never enables raw HTML here; the second pass
// also drops images and rewrites links before a browser can see them.
func renderMarkdown(source []byte, slug string, sourceSegments []string) (string, error) {
	if len(source) > maxMarkdownInput {
		return "", errMarkdownTooLarge
	}
	if !utf8.Valid(source) || bytes.IndexByte(source, 0) >= 0 {
		return "", errMarkdownUnsupportedEncoding
	}
	document := markdownEngine.Parser().Parse(text.NewReader(source))
	if err := checkMarkdownTree(document); err != nil {
		return "", err
	}
	var rendered bytes.Buffer
	if err := markdownEngine.Renderer().Render(&rendered, source, document); err != nil {
		return "", err
	}
	if rendered.Len() > maxMarkdownOutput {
		return "", errMarkdownTooLarge
	}
	return sanitizeMarkdownHTML(rendered.String(), slug, sourceSegments)
}

var (
	errMarkdownTooLarge            = errors.New("markdown exceeds rendering limit")
	errMarkdownUnsupportedEncoding = errors.New("markdown must be UTF-8 without NUL")
)

func checkMarkdownTree(root ast.Node) error {
	nodes := 0
	return ast.Walk(root, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if entering {
			nodes++
			if nodes > maxMarkdownNodes || markdownDepth(node) > maxMarkdownDepth {
				return ast.WalkStop, errMarkdownTooLarge
			}
		}
		return ast.WalkContinue, nil
	})
}

func markdownDepth(node ast.Node) int {
	depth := 0
	for current := node; current != nil; current = current.Parent() {
		depth++
	}
	return depth
}

func sanitizeMarkdownHTML(rendered, slug string, sourceSegments []string) (string, error) {
	z := html.NewTokenizer(strings.NewReader(rendered))
	var output strings.Builder
	linkStack := make([]bool, 0)
	for {
		typeID := z.Next()
		switch typeID {
		case html.ErrorToken:
			if err := z.Err(); err != io.EOF {
				return "", err
			}
			return output.String(), nil
		case html.TextToken:
			output.WriteString(stdhtml.EscapeString(string(z.Text())))
		case html.StartTagToken, html.SelfClosingTagToken:
			tag, hasAttr := z.TagName()
			name := strings.ToLower(string(tag))
			if name == "img" {
				alt := ""
				for hasAttr {
					var key, value []byte
					key, value, hasAttr = z.TagAttr()
					if strings.EqualFold(string(key), "alt") {
						alt = string(value)
					}
				}
				output.WriteString(stdhtml.EscapeString(alt))
				continue
			}
			if name == "a" {
				href := ""
				for hasAttr {
					var key, value []byte
					key, value, hasAttr = z.TagAttr()
					if strings.EqualFold(string(key), "href") {
						href = string(value)
					}
				}
				resolved, external, ok := safeMarkdownLink(href, slug, sourceSegments)
				linkStack = append(linkStack, ok)
				if ok {
					output.WriteString(`<a href="` + stdhtml.EscapeString(resolved) + `"`)
					if external {
						output.WriteString(` target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer"`)
					}
					output.WriteByte('>')
				}
				continue
			}
			for hasAttr {
				_, _, hasAttr = z.TagAttr()
			}
			if allowedMarkdownTag(name) {
				output.WriteByte('<')
				output.WriteString(name)
				output.WriteByte('>')
			}
		case html.EndTagToken:
			tag, _ := z.TagName()
			name := strings.ToLower(string(tag))
			if name == "a" {
				if len(linkStack) != 0 {
					valid := linkStack[len(linkStack)-1]
					linkStack = linkStack[:len(linkStack)-1]
					if valid {
						output.WriteString("</a>")
					}
				}
				continue
			}
			if allowedMarkdownTag(name) && name != "br" && name != "hr" {
				output.WriteString("</" + name + ">")
			}
		}
	}
}

func allowedMarkdownTag(tag string) bool {
	switch tag {
	case "p", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "pre", "code", "hr", "br", "del", "strong", "em":
		return true
	}
	return false
}

func safeMarkdownLink(raw, slug string, sourceSegments []string) (string, bool, bool) {
	u, err := url.Parse(raw)
	if err != nil || raw == "" {
		return "", false, false
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		if u.Host == "" {
			return "", false, false
		}
		return u.String(), true, true
	}
	if u.Scheme != "" || u.Host != "" || u.RawQuery != "" {
		return "", false, false
	}
	if strings.HasPrefix(u.EscapedPath(), "/") {
		segments, err := decodePathSegments(u.EscapedPath())
		if err != nil {
			return "", false, false
		}
		for _, segment := range segments {
			if isPrivateName(segment) {
				return "", false, false
			}
		}
		result := u.EscapedPath()
		if u.Fragment != "" {
			result += "#" + url.PathEscape(u.Fragment)
		}
		return result, true, true
	}
	if u.EscapedPath() == "" && u.Fragment != "" {
		return "#" + url.PathEscape(u.Fragment), false, true
	}
	base := append([]string(nil), sourceSegments...)
	if len(base) > 0 {
		base = base[:len(base)-1]
	}
	for _, piece := range strings.Split(u.EscapedPath(), "/") {
		if piece == "" || piece == "." {
			continue
		}
		if piece == ".." {
			if len(base) == 0 {
				return "", false, false
			}
			base = base[:len(base)-1]
			continue
		}
		decoded, err := decodePathSegments("/" + piece)
		if err != nil || len(decoded) != 1 || decoded[0] == "" || isPrivateName(decoded[0]) {
			return "", false, false
		}
		base = append(base, decoded[0])
	}
	if len(base) == 0 {
		return "", false, false
	}
	result := appURL(slug, base, false)
	if u.Fragment != "" {
		result += "#" + url.PathEscape(u.Fragment)
	}
	return result, false, true
}
