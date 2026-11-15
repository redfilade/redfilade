package hostile

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTagIsInvisibleAndReversible(t *testing.T) {
	enc := Tag(HiddenText)
	if utf8.RuneCountInString(enc) != len(HiddenText) {
		t.Fatalf("one tag character per ASCII character expected")
	}
	for _, r := range enc {
		if r < 0xE0000 || r > 0xE007F {
			t.Fatalf("visible character %q in tagged text", r)
		}
	}
	if Untag("Visible text"+enc) != HiddenText {
		t.Fatalf("round trip: %q", Untag(enc))
	}
	if !strings.Contains(HiddenText, BeaconTool) {
		t.Fatal("the hidden text must name the beacon tool")
	}
}

func TestSortedProbes(t *testing.T) {
	got, err := SortedProbes([]string{"all"})
	if err != nil || strings.Join(got, ",") != "elicitation,hidden_instruction,sampling" {
		t.Fatal(got, err)
	}
	if got, _ := SortedProbes([]string{"sampling", " sampling"}); len(got) != 1 {
		t.Fatal(got)
	}
	if _, err := SortedProbes([]string{"rm -rf"}); err == nil {
		t.Fatal("unknown probe accepted")
	}
}
