package reserved

import "testing"

func TestSet_noListsIsTheBuiltInSet(t *testing.T) {
	got := Set(nil, nil)
	if len(got) != len(Defaults) {
		t.Errorf("the set holds %d names, want the %d built-in ones", len(got), len(Defaults))
	}
	for _, name := range Defaults {
		if _, ok := got[name]; !ok {
			t.Errorf("built-in name %q is missing", name)
		}
	}
}

func TestSet_extraAddsAndAllowRemoves(t *testing.T) {
	got := Set([]string{"founder", "admin"}, []string{"support", "never-reserved"})
	if _, ok := got["founder"]; !ok {
		t.Error("extra must add 'founder'")
	}
	if _, ok := got["support"]; ok {
		t.Error("allow must remove 'support'")
	}
	if _, ok := got["admin"]; !ok {
		t.Error("a name in both the built-in list and extra must stay reserved")
	}
	if len(got) != len(Defaults) { // +founder, -support
		t.Errorf("the set holds %d names, want %d", len(got), len(Defaults))
	}
}

func TestSet_allowWinsOverExtra(t *testing.T) {
	got := Set([]string{"founder"}, []string{"founder"})
	if _, ok := got["founder"]; ok {
		t.Error("a name both added and allowed must not be reserved")
	}
}
