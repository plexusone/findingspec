# Installation

`findingspec` is a Go module. It requires Go 1.26 or later.

```bash
go get github.com/plexusone/findingspec
```

Import the core package and whichever domain packages you need:

```go
import (
    "github.com/plexusone/findingspec"
    "github.com/plexusone/findingspec/security"
    "github.com/plexusone/findingspec/a11y"
    "github.com/plexusone/findingspec/i18n"
    "github.com/plexusone/findingspec/qe"
)
```

## Dependencies

The core package depends only on
[`github.com/grokify/priority-frameworks`](https://github.com/grokify/priority-frameworks),
which supplies the canonical severity vocabulary, ordering, and CVSS score
mapping. Domain packages depend only on the core.

## Building the docs

This documentation is built with [MkDocs](https://www.mkdocs.org/) and the
[Material](https://squidfunk.github.io/mkdocs-material/) theme:

```bash
pip install mkdocs mkdocs-material
mkdocs serve   # live preview at http://127.0.0.1:8000
mkdocs build   # render the static site to ./site
```
