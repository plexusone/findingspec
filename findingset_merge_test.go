package findingspec_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/plexusone/findingspec"
)

func TestMerge(t *testing.T) {
	a := findingspec.NewFindingSet(findingspec.Finding{ID: "CF-c1-lessPrecise"}, findingspec.Finding{ID: "CF-c2-duplicate"})
	b := findingspec.NewFindingSet(findingspec.Finding{ID: "AV-c1-audioDisputed"})
	got, err := findingspec.Merge(a, nil, b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 3 || got.Findings[2].ID != "AV-c1-audioDisputed" {
		t.Errorf("merged = %+v", got.Findings)
	}
	_, err = findingspec.Merge(a, findingspec.NewFindingSet(findingspec.Finding{ID: "CF-c2-duplicate"}))
	if !errors.Is(err, findingspec.ErrDuplicateID) || !strings.Contains(err.Error(), "CF-c2-duplicate") {
		t.Errorf("err = %v, want ErrDuplicateID naming CF-c2-duplicate", err)
	}
}
