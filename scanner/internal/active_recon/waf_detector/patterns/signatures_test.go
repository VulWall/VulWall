package patterns

import (
	"testing"
)

func TestSignatureCompilation(t *testing.T) {
	err := CompileSignatures(AllSignatures)
	if err != nil {
		t.Fatalf("Failed to compile signatures: %v", err)
	}
}

func TestSignatureCount(t *testing.T) {
	count := len(AllSignatures)
	if count < 60 {
		t.Errorf("Expected at least 60 signatures, got %d", count)
	}
	t.Logf("Total signatures: %d", count)
}

func TestEUWAFSignatures(t *testing.T) {
	euWAFs := []string{
		"Airlock",
		"TransIP Web Firewall",
		"NinjaFirewall",
		"WebARX",
		"NevisProxy",
		"WatchGuard",
		"IBM WebSEAL",
		"ZScaler",
		"IBM DataPower",
		"Qrator",
		"PT Application Firewall",
		"HyperGuard",
		"GreyWizard",
		"Google Cloud Armor",
		"LiteSpeed",
		"Shield Security",
		"Microsoft URLScan",
		"Microsoft RequestValidationMode",
		"Mission Control Shield",
		"Profense",
		"Link11 WAAP",
	}

	found := make(map[string]bool)
	for _, sig := range AllSignatures {
		found[sig.Name] = true
	}

	missing := []string{}
	for _, wafName := range euWAFs {
		if !found[wafName] {
			missing = append(missing, wafName)
		}
	}

	if len(missing) > 0 {
		t.Errorf("Missing EU WAF signatures: %v", missing)
	} else {
		t.Logf("All %d EU WAF signatures present", len(euWAFs))
	}
}

func TestSignaturePriorities(t *testing.T) {
	for _, sig := range AllSignatures {
		if sig.Priority < 0 || sig.Priority > 100 {
			t.Errorf("Signature %s has invalid priority: %d", sig.Name, sig.Priority)
		}
		if sig.Name == "" {
			t.Error("Found signature with empty name")
		}
		if sig.Vendor == "" {
			t.Errorf("Signature %s has empty vendor", sig.Name)
		}
		if len(sig.Checks) == 0 {
			t.Errorf("Signature %s has no checks", sig.Name)
		}
	}
}

func TestCheckPatterns(t *testing.T) {
	for _, sig := range AllSignatures {
		for _, check := range sig.Checks {
			if check.Type == "" {
				t.Errorf("Signature %s has check with empty type", sig.Name)
			}
			if check.Pattern == "" && check.Type != CheckTypeCode {
				t.Errorf("Signature %s has check with empty pattern (type: %s)", sig.Name, check.Type)
			}
			// Header and cookie checks should have a key
			if (check.Type == CheckTypeHeader || check.Type == CheckTypeCookie) && check.Pattern == "" {
				t.Errorf("Signature %s has header/cookie check without pattern", sig.Name)
			}
		}
	}
}
