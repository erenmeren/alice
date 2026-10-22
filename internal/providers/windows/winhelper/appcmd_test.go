package winhelper

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"alice/internal/providers/windows/winproto"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseAppcmdSites(t *testing.T) {
	sites, err := ParseAppcmdSites(readFixture(t, "appcmd-two-sites.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []winproto.Site{
		{Name: "Shop", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{
			{Protocol: "https", Information: "*:443:www.example.test", SSLFlags: 1},
			{Protocol: "https", Information: "10.0.0.5:8443:", SSLFlags: 0}}},
		{Name: "Admin & Co", ID: 2, State: "Stopped", Bindings: []winproto.SiteBinding{
			{Protocol: "https", Information: "*:9443:", SSLFlags: 3}}},
	}
	if !reflect.DeepEqual(sites, want) {
		t.Fatalf("got %+v\nwant %+v", sites, want)
	}
}

// The captures are real "appcmd list site /config /xml" outputs of the W0 spike runners (doubled CRLF
// line endings, many non-binding child elements, the state on the SITE wrapper).
func TestParseAppcmdSitesRealCaptures(t *testing.T) {
	for _, name := range []string{"appcmd-ws2022.xml", "appcmd-ws2025.xml"} {
		t.Run(name, func(t *testing.T) {
			sites, err := ParseAppcmdSites(readFixture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			want := []winproto.Site{
				{Name: "Default Web Site", ID: 1, State: "Started", Bindings: []winproto.SiteBinding{}},
				{Name: "spike", ID: 9001, State: "Started", Bindings: []winproto.SiteBinding{
					{Protocol: "https", Information: "*:8443:"},
					{Protocol: "https", Information: "*:8444:sni.spike.test", SSLFlags: 1},
					{Protocol: "https", Information: "*:8446:"},
					{Protocol: "https", Information: "*:8447:mwa.spike.test", SSLFlags: 1}}},
			}
			if !reflect.DeepEqual(sites, want) {
				t.Fatalf("got %+v\nwant %+v", sites, want)
			}
		})
	}
}

func TestParseAppcmdSitesRefusals(t *testing.T) {
	for name, in := range map[string]string{
		"doctype":       `<?xml version="1.0"?><!DOCTYPE appcmd [<!ENTITY x "y">]><appcmd/>`,
		"doctype lower": `<!doctype appcmd><appcmd/>`,
		"not xml":       `this is not xml`,
		"empty":         ``,
		"truncated":     `<appcmd><SITE SITE.NAME="a" SITE.ID="1"><site name="a" id="1">`,
		"wrong root":    `<other/>`,
		"bad inner":     `<appcmd><SITE><site><bindings><binding></site></SITE></appcmd>`,
		"bad skipped":   `<appcmd><junk><a></junk></appcmd>`,
	} {
		if _, err := ParseAppcmdSites([]byte(in)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := ParseAppcmdSites(make([]byte, winproto.MaxAppcmdOutput+1)); err == nil {
		t.Error("oversized input accepted")
	}
}

func TestParseAppcmdSitesCleansAndDrops(t *testing.T) {
	long := strings.Repeat("a", 300)
	in := fmt.Sprintf(`<appcmd>
<SITE><site name="%s" id="7" ><bindings><binding protocol="HTTPS" bindingInformation="*:443:x" sslFlags="x"/>
<binding protocol="https" bindingInformation="*:444:%s" /><binding protocol="https" bindingInformation="  " /></bindings></site></SITE>
<SITE SITE.NAME="wrapper" SITE.ID="8" state="Started"><site><bindings><binding protocol="https" bindingInformation="*:445:" sslFlags="-1"/></bindings></site></SITE>
<SITE><site name="noid" id="abc"/></SITE>
<SITE><site name="" id="9"/></SITE>
</appcmd>`, long, long)
	sites, truncated, err := parseSites([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("dropped records not reported")
	}
	if len(sites) != 2 {
		t.Fatalf("%+v", sites)
	}
	if len(sites[0].Name) != winproto.MaxText || sites[0].ID != 7 {
		t.Errorf("name not cut: %d", len(sites[0].Name))
	}
	if len(sites[0].Bindings) != 1 || len(sites[0].Bindings[0].Information) != winproto.MaxText {
		t.Errorf("bindings: %+v", sites[0].Bindings)
	}
	// wrapper attributes are the fallback when the inner element has none
	if sites[1].Name != "wrapper" || sites[1].ID != 8 || sites[1].State != "Started" || len(sites[1].Bindings) != 0 {
		t.Errorf("%+v", sites[1])
	}
}

func TestParseAppcmdSitesBounds(t *testing.T) {
	var b strings.Builder
	b.WriteString("<appcmd>")
	for i := 1; i <= winproto.MaxSites+1; i++ {
		fmt.Fprintf(&b, `<SITE><site name="s%d" id="%d"/></SITE>`, i, i)
	}
	b.WriteString("</appcmd>")
	sites, truncated, err := parseSites([]byte(b.String()))
	if err != nil || !truncated || len(sites) != winproto.MaxSites || sites[winproto.MaxSites-1].Name != fmt.Sprintf("s%d", winproto.MaxSites) {
		t.Fatalf("%v %v %d", err, truncated, len(sites))
	}
	if exported, err := ParseAppcmdSites([]byte(b.String())); err != nil || len(exported) != winproto.MaxSites {
		t.Fatalf("%v %d", err, len(exported))
	}
	// the binding total is bounded too
	b.Reset()
	b.WriteString("<appcmd>")
	for i := 1; i <= 11; i++ {
		fmt.Fprintf(&b, `<SITE><site name="s%d" id="%d"><bindings>`, i, i)
		for j := 0; j < 1000; j++ {
			fmt.Fprintf(&b, `<binding protocol="https" bindingInformation="*:%d:"/>`, 1+j)
		}
		b.WriteString(`</bindings></site></SITE>`)
	}
	b.WriteString("</appcmd>")
	sites, truncated, err = parseSites([]byte(b.String()))
	total := 0
	for _, s := range sites {
		total += len(s.Bindings)
	}
	if err != nil || !truncated || total != winproto.MaxSiteBindings {
		t.Fatalf("%v %v %d", err, truncated, total)
	}
}
