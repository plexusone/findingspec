# Location

`Location` describes where a finding was observed. Its fields are intentionally
domain-flexible so one type can locate a finding regardless of how the artifact
is represented — source code, a live page, or a node inside a structured
document.

## Location

`Location` is attached to a [Finding](../concepts/finding-model.md) as
`*Location`; a `nil` pointer or an empty value means the location is unknown.

| Field | Type | Notes |
|-------|------|-------|
| `Repo` | `string` | Repository or workspace the finding belongs to, when a producer scans more than one (a path, URL, or module name) |
| `File` | `string` | Repository-relative source path |
| `Line` | `int` | 1-indexed line number within `File` |
| `Column` | `int` | 1-indexed column within `Line` |
| `URL` | `string` | Address of the page or endpoint where the finding was observed |
| `Selector` | `string` | CSS or XPath selector identifying a DOM element |
| `Component` | `string` | Logical component, module, or capability name |
| `Pointer` | `string` | RFC 6901 JSON Pointer to a node within a structured document |
| `DocFormat` | `string` | Structured-document format `File`/`Pointer` refer to, e.g. `"openapi"`, `"postman"`, `"json"`, `"yaml"` |
| `Snippet` | `string` | Short excerpt of the offending code or markup |

All fields are optional (`omitempty`); a producer sets only those that apply.

## Three ways to locate a finding

Different domains observe findings at different layers, so `Location` supports
three complementary addressing schemes. A producer picks the one that fits, and
may combine them (for example `Component` alongside any of the others).

### Code — `File` / `Line` / `Column`

Code-level findings (security, i18n) point at a source path with a line and,
optionally, a column:

```go
loc := findingspec.Location{
    File:   "internal/auth/token.go",
    Line:   42,
    Column: 9,
}
```

### Runtime UI — `URL` / `Selector`

Runtime findings (a11y, qe) point at the page where the issue appeared and the
DOM element within it:

```go
loc := findingspec.Location{
    URL:      "https://app.example.com/checkout",
    Selector: "button.pay-now",
}
```

### Structured document — `Pointer` (RFC 6901) + `DocFormat`

A node inside a JSON or YAML document is addressed with an
[RFC 6901](https://www.rfc-editor.org/rfc/rfc6901) JSON Pointer in `Pointer`,
qualified by `DocFormat`. Unlike `Line`/`Column`, a JSON Pointer is **stable
across reformatting** — reindenting, reordering keys, or converting YAML to JSON
does not change the pointer, whereas any of those shifts every line number. Use
`Pointer` in preference to `Line`/`Column` for structured files.

An OpenAPI document, pointing at a leaked default for a server variable:

```go
loc := findingspec.Location{
    File:      "openapi.yaml",
    DocFormat: "openapi",
    Pointer:   "/servers/0/variables/apiKey/default",
}
```

A Postman collection, pointing at a request header value:

```go
loc := findingspec.Location{
    File:      "collection.json",
    DocFormat: "postman",
    Pointer:   "/item/2/request/header/1/value",
}
```

## Multi-repo and monorepo sweeps

`Repo` identifies which repository or workspace a finding belongs to when a
producer scans more than one — a multi-repo sweep, or a monorepo with several
workspaces. It may be a path, URL, or module name, at the producer's discretion.
Leave it empty when a producer only ever scans a single, implicit repository.

## `Empty()`

`Empty` reports whether the location carries no information (all fields at their
zero value):

```go
func (l Location) Empty() bool
```

```go
var loc findingspec.Location
loc.Empty() // true

loc.File = "main.go"
loc.Empty() // false
```

## See also

- [Security domain](../domains/security.md) — locating secrets in structured documents such as OpenAPI and Postman
- [Finding model](../concepts/finding-model.md) — how `Location` fits into a `Finding`
