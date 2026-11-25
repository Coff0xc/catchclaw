package payload

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
)

type MutationType string

const (
	MutUnicodeHomoglyph MutationType = "unicode_homoglyph"
	MutBase64Wrap       MutationType = "base64_wrap"
	MutHexWrap          MutationType = "hex_wrap"
	MutJunkPadding      MutationType = "junk_padding"
	MutURLEncode        MutationType = "url_encode"
	MutDoubleURLEncode  MutationType = "double_url_encode"
	MutUnicodeEscape    MutationType = "unicode_escape"
	MutHTMLEntity       MutationType = "html_entity"
	MutCaseVariation    MutationType = "case_variation"
)

func Mutate(base string, mtype MutationType) string {
	switch mtype {
	case MutUnicodeHomoglyph:
		return unicodeHomoglyph(base)
	case MutBase64Wrap:
		return base64.StdEncoding.EncodeToString([]byte(base))
	case MutHexWrap:
		return hex.EncodeToString([]byte(base))
	case MutJunkPadding:
		return addJunk(base, 2)
	case MutURLEncode:
		return url.QueryEscape(base)
	case MutDoubleURLEncode:
		return url.QueryEscape(url.QueryEscape(base))
	case MutUnicodeEscape:
		return unicodeEscape(base)
	case MutHTMLEntity:
		return htmlEntityEncode(base)
	case MutCaseVariation:
		return caseVariation(base)
	default:
		return base
	}
}

func MutateChain(base string, chain []MutationType) string {
	result := base
	for _, m := range chain {
		result = Mutate(result, m)
	}
	return result
}

func StealthChain() []MutationType {
	return []MutationType{MutUnicodeHomoglyph, MutJunkPadding}
}

func HeavyChain() []MutationType {
	return []MutationType{MutUnicodeHomoglyph, MutCaseVariation, MutJunkPadding}
}

func unicodeHomoglyph(input string) string {
	replacer := strings.NewReplacer(
		"/", "∕",
		".", "․",
		"A", "Α",
		"B", "Β",
		"E", "Ε",
		"O", "Ο",
		"P", "Ρ",
		"H", "Η",
		"C", "С",
		"a", "а",
		"c", "с",
		"e", "е",
		"o", "о",
		"p", "р",
		"x", "х",
		"y", "у",
	)
	return replacer.Replace(input)
}

func addJunk(input string, intensity int) string {
	var sb strings.Builder
	junkChars := []rune{' ', '\t', '\n', '\r', '​'}
	for _, c := range input {
		sb.WriteRune(c)
		if rand.Float64() < 0.1*float64(intensity) {
			sb.WriteRune(junkChars[rand.Intn(len(junkChars))])
		}
	}
	return sb.String()
}

func unicodeEscape(input string) string {
	var sb strings.Builder
	for _, c := range input {
		fmt.Fprintf(&sb, "\\u%04x", c)
	}
	return sb.String()
}

func htmlEntityEncode(input string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	)
	return replacer.Replace(input)
}

func caseVariation(input string) string {
	var sb strings.Builder
	for _, c := range input {
		if rand.Float64() < 0.5 {
			if c >= 'a' && c <= 'z' {
				sb.WriteRune(c - 32)
				continue
			}
			if c >= 'A' && c <= 'Z' {
				sb.WriteRune(c + 32)
				continue
			}
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
