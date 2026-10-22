package winhelper

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"

	"alice/internal/providers/windows/winproto"
)

// xmlSite is one SITE element of "appcmd list site /config /xml": the wrapper carries SITE.NAME,
// SITE.ID and the state (W0 F6: a lower-case "state" on the real output), the inner site element the
// configuration. Everything else in the element is ignored.
type xmlSite struct {
	Name   string `xml:"SITE.NAME,attr"`
	ID     string `xml:"SITE.ID,attr"`
	State  string `xml:"state,attr"`
	StateU string `xml:"STATE,attr"`
	Inner  struct {
		Name     string `xml:"name,attr"`
		ID       string `xml:"id,attr"`
		Bindings []struct {
			Protocol    string `xml:"protocol,attr"`
			Information string `xml:"bindingInformation,attr"`
			SSLFlags    string `xml:"sslFlags,attr"`
		} `xml:"bindings>binding"`
	} `xml:"site"`
}

var errAppcmdXML = errors.New("winhelper: the appcmd output is not usable")

// ParseAppcmdSites reads the output of "appcmd list site /config /xml" and returns the sites with
// their https bindings only (other protocols are dropped, a site without https bindings stays with an
// empty list). At most winproto.MaxSites sites and winproto.MaxSiteBindings bindings are returned.
// Input over winproto.MaxAppcmdOutput or containing a DOCTYPE is refused; the standard library's
// decoder expands only the five predefined entities.
func ParseAppcmdSites(data []byte) ([]winproto.Site, error) {
	sites, _, err := parseSites(data)
	return sites, err
}

// parseSites is ParseAppcmdSites plus "something was cut or dropped": more sites or bindings than the
// bounds, or a site or binding that could not be read.
func parseSites(data []byte) ([]winproto.Site, bool, error) {
	if len(data) > winproto.MaxAppcmdOutput || bytes.Contains(bytes.ToUpper(data), []byte("<!DOCTYPE")) {
		return nil, false, errAppcmdXML
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	sites := []winproto.Site{}
	truncated, rootSeen, bindingsSeen := false, false, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, false, errAppcmdXML
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootSeen {
			if se.Name.Local != "appcmd" {
				return nil, false, errAppcmdXML
			}
			rootSeen = true
			continue
		}
		if se.Name.Local != "SITE" {
			if err := dec.Skip(); err != nil {
				return nil, false, errAppcmdXML
			}
			continue
		}
		var xs xmlSite
		if err := dec.DecodeElement(&xs, &se); err != nil {
			return nil, false, errAppcmdXML
		}
		if len(sites) == winproto.MaxSites {
			truncated = true
			continue
		}
		site, cut, ok := convertSite(xs, &bindingsSeen)
		truncated = truncated || cut || !ok
		if ok {
			sites = append(sites, site)
		}
	}
	if !rootSeen {
		return nil, false, errAppcmdXML
	}
	return sites, truncated, nil
}

// convertSite cleans one site; cut reports a dropped or cut binding, ok false a site that was dropped.
func convertSite(xs xmlSite, bindingsSeen *int) (site winproto.Site, cut, ok bool) {
	name, idText, state := xs.Inner.Name, xs.Inner.ID, xs.State
	if name == "" {
		name = xs.Name
	}
	if idText == "" {
		idText = xs.ID
	}
	if state == "" {
		state = xs.StateU
	}
	id, err := strconv.ParseInt(strings.TrimSpace(idText), 10, 64)
	name = cleanValue(name, winproto.MaxText)
	if err != nil || id < 0 || name == "" {
		return winproto.Site{}, false, false
	}
	site = winproto.Site{Name: name, ID: id, State: cleanValue(state, winproto.MaxText), Bindings: []winproto.SiteBinding{}}
	for _, b := range xs.Inner.Bindings {
		if !strings.EqualFold(b.Protocol, "https") {
			continue
		}
		if *bindingsSeen == winproto.MaxSiteBindings {
			return site, true, true
		}
		flags := 0
		if b.SSLFlags != "" {
			if flags, err = strconv.Atoi(strings.TrimSpace(b.SSLFlags)); err != nil || flags < 0 {
				cut = true
				continue
			}
		}
		info := cleanValue(b.Information, winproto.MaxText)
		if info == "" {
			cut = true
			continue
		}
		*bindingsSeen++
		site.Bindings = append(site.Bindings, winproto.SiteBinding{Protocol: "https", Information: info, SSLFlags: flags})
	}
	return site, cut, true
}
