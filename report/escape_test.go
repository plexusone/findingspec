package report

import "testing"

func TestEscapeText(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain words", "plain words"},
		{"a *b* _c_ <d> @e $f & g", `a \*b\* \_c\_ \<d\> \@e \$f \& g`},
		{"keep `x_y | z` as code", "keep `x_y \\| z` as code"},
		{"``a ` b`` then *", "``a ` b`` then \\*"},
		{"unmatched ` tick", "unmatched \\` tick"},
		{"- dash", `\- dash`},
		{"+ plus", `\+ plus`},
		{"===", `\===`},
		{": colon", `\: colon`},
		{"12. item", `12\. item`},
		{"3) item", `3\) item`},
		{"1.1.1 is a version", "1.1.1 is a version"},
		{"# hash", `\# hash`},
		{"> quote", `\> quote`},
		{"    indented code", "indented code"},
		{"para one\n\npara two", "para one\n\npara two"},
	}
	for _, tt := range tests {
		if got := escapeText(tt.in); got != tt.want {
			t.Errorf("escapeText(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEscapeInlineSkipsLineStartGuards(t *testing.T) {
	if got := escapeInline("1. first\n- second"); got != "1. first - second" {
		t.Errorf("escapeInline = %q", got)
	}
}

func TestCodeSpan(t *testing.T) {
	tests := []struct{ in, want string }{
		{"a.go:1", "`a.go:1`"},
		{"has ` tick", "``has ` tick``"},
		{"`edge`", "`` `edge` ``"},
		{"a|b", "`a\\|b`"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := codeSpan(tt.in); got != tt.want {
			t.Errorf("codeSpan(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestAnchor(t *testing.T) {
	if got := anchor("SF-OAUTH 001/é"); got != "finding-sf-oauth-001--" {
		t.Errorf("anchor = %q", got)
	}
}
