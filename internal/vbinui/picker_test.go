package vbinui

import "testing"

func TestRankChoicesPrefersContiguousEarlyMatch(t *testing.T) {
	choices := []Choice{
		{Label: "staging-production-copy", Value: "copy"},
		{Label: "production", Value: "prod"},
		{Label: "pre operation", Value: "scattered"},
	}
	ranked := RankChoices(choices, "prod")
	if len(ranked) != 2 {
		t.Fatalf("got %d matches, want 2: %#v", len(ranked), ranked)
	}
	if ranked[0].Value != "prod" {
		t.Fatalf("top match = %q, want production", ranked[0].Value)
	}
}

func TestSelectChoiceSupportsDeterministicIndex(t *testing.T) {
	choices := []Choice{{Label: "alpha", Value: "a"}, {Label: "beta", Value: "b"}}
	selected, err := SelectChoice(choices, SelectOptions{Query: "a", Index: 1, NonInteractive: true})
	if err != nil {
		t.Fatal(err)
	}
	if selected.Value != "b" {
		t.Fatalf("selected %q, want b", selected.Value)
	}
}
