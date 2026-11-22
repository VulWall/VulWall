package knowledge_base

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// kbEntry is the part of a generated entry that validateEntry checks. The
// published entry is the full JSON object, not this struct.
type kbEntry struct {
	Business struct {
		Title    string   `json:"title"`
		Summary  string   `json:"summary"`
		Impact   string   `json:"impact"`
		Urgency  string   `json:"urgency"`
		Actions  []string `json:"actions"`
		BlogSlug string   `json:"blog_slug"`
	} `json:"business"`
	Technical struct {
		Title                    string `json:"title"`
		VulnerabilityExplanation string `json:"vulnerability_explanation"`
		RootCause                string `json:"root_cause"`
		Impact                   string `json:"impact"`
		Severity                 struct {
			Level         string `json:"level"`
			Justification string `json:"justification"`
		} `json:"severity"`
		RemediationSteps  []string `json:"remediation_steps"`
		VerificationSteps []string `json:"verification_steps"`
		BlogSlug          string   `json:"blog_slug"`
	} `json:"technical"`
	Metadata struct {
		OWASPCategory   string `json:"owasp_category"`
		EstimatedEffort string `json:"estimated_effort"`
		IsExploitable   *bool  `json:"is_exploitable"`
	} `json:"metadata"`
}

var slugPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// validateEntry checks a generated entry beyond what the JSON Schema
// enforces: every section is present, enums hold known values, and the text
// fields are long enough to be useful. Providers without strict schema
// output depend on it; for Anthropic it catches empty or stub answers.
func validateEntry(raw json.RawMessage) error {
	var e kbEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return fmt.Errorf("entry is not a JSON object: %w", err)
	}
	var problems []error
	text := func(field, value string, minLen int) {
		if n := len(strings.TrimSpace(value)); n < minLen {
			problems = append(problems, fmt.Errorf("%s: %d characters, want at least %d", field, n, minLen))
		}
	}
	list := func(field string, items []string, minItems, maxItems, minLen int) {
		if len(items) < minItems || len(items) > maxItems {
			problems = append(problems, fmt.Errorf("%s: %d items, want %d to %d", field, len(items), minItems, maxItems))
		}
		for i, item := range items {
			text(fmt.Sprintf("%s[%d]", field, i), item, minLen)
		}
	}
	oneOf := func(field, value string, allowed ...string) {
		if !slices.Contains(allowed, value) {
			problems = append(problems, fmt.Errorf("%s: %q is not one of %v", field, value, allowed))
		}
	}
	slug := func(field, value string) {
		if !slugPattern.MatchString(value) {
			problems = append(problems, fmt.Errorf("%s: %q is not a URL slug", field, value))
		}
	}

	b := e.Business
	text("business.title", b.Title, 5)
	text("business.summary", b.Summary, 40)
	text("business.impact", b.Impact, 40)
	oneOf("business.urgency", b.Urgency, "immediate", "high", "medium", "low")
	list("business.actions", b.Actions, 1, 6, 10)
	slug("business.blog_slug", b.BlogSlug)

	t := e.Technical
	text("technical.title", t.Title, 5)
	text("technical.vulnerability_explanation", t.VulnerabilityExplanation, 40)
	text("technical.root_cause", t.RootCause, 20)
	text("technical.impact", t.Impact, 20)
	oneOf("technical.severity.level", t.Severity.Level, "critical", "high", "medium", "low", "info")
	text("technical.severity.justification", t.Severity.Justification, 10)
	list("technical.remediation_steps", t.RemediationSteps, 1, 10, 10)
	list("technical.verification_steps", t.VerificationSteps, 1, 10, 10)
	slug("technical.blog_slug", t.BlogSlug)

	m := e.Metadata
	text("metadata.owasp_category", m.OWASPCategory, 2)
	oneOf("metadata.estimated_effort", m.EstimatedEffort, "trivial", "small", "medium", "large")
	if m.IsExploitable == nil {
		problems = append(problems, errors.New("metadata.is_exploitable: missing"))
	}

	return errors.Join(problems...)
}

// normalizeEntry decodes a validated entry for publishing. technical.references
// keeps only http(s) URLs, and is always null without web search: URLs the
// model writes from memory are often wrong.
func normalizeEntry(raw json.RawMessage, webSearch bool) (map[string]any, error) {
	var entry map[string]any
	if err := json.Unmarshal(raw, &entry); err != nil {
		return nil, fmt.Errorf("decode entry: %w", err)
	}
	technical, ok := entry["technical"].(map[string]any)
	if !ok {
		return nil, errors.New("entry has no technical section")
	}
	var refs []any
	if webSearch {
		items, _ := technical["references"].([]any)
		for _, item := range items {
			if s, ok := item.(string); ok && isWebURL(s) {
				refs = append(refs, strings.TrimSpace(s))
			}
		}
	}
	if len(refs) == 0 {
		technical["references"] = nil
	} else {
		technical["references"] = refs
	}
	return entry, nil
}

func isWebURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}
