package report

import (
	"encoding/json"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// inlineSpecials are characters that can start Markdown or pandoc inline
// syntax. A backslash escape is valid for each in pandoc Markdown and in
// CommonMark.
const inlineSpecials = "\\`*_[]<>#|~^$@&"

// escapeText escapes plain text for use in a Markdown paragraph. Blank lines
// still separate paragraphs; each line is stripped of leading indentation and
// guarded against being read as a list, heading, or block quote.
func escapeText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = escapeLine(strings.TrimLeft(line, " \t"))
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// escapeLine escapes one line of text that will start a Markdown line.
func escapeLine(line string) string {
	return guardLineStart(escapeSpecials(line))
}

// escapeSpecials backslash-escapes inline syntax, keeping matched code spans.
func escapeSpecials(line string) string {
	var b strings.Builder
	b.Grow(len(line) + 8)
	for i := 0; i < len(line); {
		if line[i] == '`' {
			if span, ok := codeSpanAt(line[i:]); ok {
				b.WriteString(strings.ReplaceAll(span, "|", "\\|"))
				i += len(span)
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		if strings.ContainsRune(inlineSpecials, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// guardLineStart escapes markers that only have meaning at the start of a
// line: list bullets, setext underlines, definition lists, ordered lists.
func guardLineStart(out string) string {
	if out == "" {
		return out
	}
	// Block-level markers that are only special at the start of a line.
	switch out[0] {
	case '-', '+', '=', ':':
		return "\\" + out
	}
	// Ordered-list markers: digits followed by '.' or ')'.
	digits := 0
	for digits < len(out) && out[digits] >= '0' && out[digits] <= '9' {
		digits++
	}
	if digits > 0 && digits < len(out) && (out[digits] == '.' || out[digits] == ')') &&
		(digits+1 == len(out) || out[digits+1] == ' ' || out[digits+1] == '\t') {
		return out[:digits] + "\\" + out[digits:]
	}
	return out
}

// codeSpanAt reports whether s begins with a complete inline code span (a
// backtick run closed by a run of the same length) and returns it. Authors
// commonly mark identifiers this way, so such spans are kept as code rather
// than escaped.
func codeSpanAt(s string) (string, bool) {
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	for i := n; i < len(s); {
		if s[i] != '`' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] == '`' {
			j++
		}
		if j-i == n {
			if strings.TrimSpace(s[n:i]) == "" {
				return "", false
			}
			return s[:j], true
		}
		i = j
	}
	return "", false
}

// escapeInline escapes text for a single-line context such as a table cell
// or list item, folding all whitespace runs to single spaces. The text never
// starts a line, so line-start markers are left alone.
func escapeInline(s string) string {
	return escapeSpecials(strings.Join(strings.Fields(s), " "))
}

// codeSpan wraps s in an inline code span whose backtick fence is longer than
// any backtick run inside s.
func codeSpan(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if s == "" {
		return ""
	}
	fence := strings.Repeat("`", longestRun(s, '`')+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	// A pipe would still end a table cell inside a code span.
	s = strings.ReplaceAll(s, "|", "\\|")
	return fence + s + fence
}

// codeBlock returns a fenced code block whose fence cannot be closed by the
// content.
func codeBlock(content, lang string) string {
	fence := strings.Repeat("`", max(3, longestRun(content, '`')+1))
	return fence + lang + "\n" + strings.TrimRight(content, "\n") + "\n" + fence
}

func longestRun(s string, c rune) int {
	best, cur := 0, 0
	for _, r := range s {
		if r == c {
			cur++
			best = max(best, cur)
		} else {
			cur = 0
		}
	}
	return best
}

// langForFile returns a code-block language for a file name, or "".
func langForFile(file string) string {
	switch strings.ToLower(path.Ext(file)) {
	case ".go":
		return "go"
	case ".js", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".rb":
		return "ruby"
	case ".rs":
		return "rust"
	case ".sql":
		return "sql"
	case ".sh", ".bash":
		return "bash"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	case ".html", ".htm":
		return "html"
	case ".tf", ".hcl":
		return "hcl"
	default:
		return ""
	}
}

// anchor returns a header identifier for a finding ID.
func anchor(id string) string {
	var b strings.Builder
	b.WriteString("finding-")
	for _, r := range strings.ToLower(id) {
		switch {
		case r < unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsDigit(r)), r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// linkURL makes a URL safe as a Markdown link destination.
func linkURL(u string) string {
	return strings.NewReplacer(" ", "%20", "(", "%28", ")", "%29", "<", "%3C", ">", "%3E").Replace(strings.TrimSpace(u))
}

// yamlString quotes s as a YAML double-quoted scalar. Pandoc reads metadata
// values as Markdown, so the text is escaped first.
func yamlString(s string) (string, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	// Pandoc parses each value as a Markdown block, so guard the line start.
	if err := enc.Encode(escapeLine(strings.Join(strings.Fields(s), " "))); err != nil {
		return "", err
	}
	return strings.TrimSpace(b.String()), nil
}

// humanize turns an enum value such as "false_positive" into "False positive".
func humanize(s string) string {
	s = strings.NewReplacer("_", " ", "-", " ").Replace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
