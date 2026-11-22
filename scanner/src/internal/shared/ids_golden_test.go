package shared

import "testing"

// The web app computes the same discovery ids when an asset is added (it records the new asset
// on the discoveries a scan already found: web/src/Verticals/Assets/Services/DiscoveryIds.cs).
// DiscoveryIdsTests in the web tests holds these same vectors; change both together.
func TestDiscoveryIDGoldenVectors(t *testing.T) {
	const org = "65f0c0ffee0000000000abcd"
	for _, c := range []struct{ name, got, want string }{
		{"domain", GenerateDomainID(org, "example.com"), "c750680d-fe91-5c52-871d-d2751c65d19d"},
		{"domain, case and spaces", GenerateDomainID(org, " Example.COM "), "c750680d-fe91-5c52-871d-d2751c65d19d"},
		{"subdomain", GenerateSubdomainID(org, "api.example.com"), "5dbd06f6-a96c-52c2-9d3a-3f979ee58a22"},
		{"subdomain, case and spaces", GenerateSubdomainID(org, " API.Example.com "), "5dbd06f6-a96c-52c2-9d3a-3f979ee58a22"},
		{"two-dot root", GenerateSubdomainID(org, "example.co.uk"), "6ac63044-880f-552b-a23d-ce54cb86db1d"},
		{"ip", GenerateIPID(org, "203.0.113.7"), "940e7b5d-6133-51a7-97f6-eeddda89bd0d"},
		{"ip, spaces", GenerateIPID(org, " 203.0.113.7 "), "940e7b5d-6133-51a7-97f6-eeddda89bd0d"},
		{"ipv6, case kept", GenerateIPID(org, "2001:DB8::1"), "8133bac8-3893-5e76-9dd1-ef57a074e319"},
		{"other org", GenerateDomainID("org-2", "example.com"), "1f0f89da-6576-5075-884c-73d154cc6be6"},
	} {
		if c.got != c.want {
			t.Errorf("%s: id = %s, want %s", c.name, c.got, c.want)
		}
	}
}
