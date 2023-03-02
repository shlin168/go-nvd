package schema

import "encoding/xml"

// MitreCpeList is the xml format for stale CPE xml files
//
// ref. https://nvd.nist.gov/products/cpe
type MitreCpeList struct {
	XMLName        xml.Name `xml:"cpe-list"`
	Text           string   `xml:",chardata"`
	Config         string   `xml:"config,attr"`
	Xmlns          string   `xml:"xmlns,attr"`
	Xsi            string   `xml:"xsi,attr"`
	ScapCore       string   `xml:"scap-core,attr"`
	Cpe23          string   `xml:"cpe-23,attr"`
	Ns6            string   `xml:"ns6,attr"`
	Meta           string   `xml:"meta,attr"`
	SchemaLocation string   `xml:"schemaLocation,attr"`
	Generator      struct {
		Text           string `xml:",chardata"`
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator"`
	CpeItem []MitreCpe `xml:"cpe-item"`
}

// MitreCpe is the stale format for each cpe.
//
// E.g.,
//
//	<cpe-item name="cpe:/a:01org:tpm2.0-tools:1.1.0">
//	    <title xml:lang="en-US">01org Tpm2.0-tools 1.1.0</title>
//	    <references>
//	        <reference href="https://github.com/01org/tpm2.0-tools">Product</reference>
//	        <reference href="https://github.com/01org">Vendor</reference>
//	    </references>
//	    <cpe-23:cpe23-item name="cpe:2.3:a:01org:tpm2.0-tools:1.1.0:*:*:*:*:*:*:*"/>
//	 </cpe-item>
type MitreCpe struct {
	Text  string `xml:",chardata"`
	Name  string `xml:"name,attr"`
	Title struct {
		Text string `xml:",chardata"`
		Lang string `xml:"lang,attr"`
	} `xml:"title"`
	References struct {
		Text      string `xml:",chardata"`
		Reference []struct {
			Text string `xml:",chardata"`
			Href string `xml:"href,attr"`
		} `xml:"reference"`
	} `xml:"references"`
	Cpe23Item struct {
		Text string `xml:",chardata"`
		Name string `xml:"name,attr"`
	} `xml:"cpe23-item"`
}

// ToAPIStruct converts mitre format to nvd cpe format
func (c MitreCpe) ToAPIStruct() Cpe {
	cpe := Cpe{
		Name:   c.Cpe23Item.Name,
		Titles: []Title{{Title: c.Title.Text, Lang: c.Title.Lang}},
	}
	for _, ref := range c.References.Reference {
		cpe.References = append(cpe.References, ReferenceCpe{
			Ref:  ref.Href,
			Type: ref.Text,
		})
	}
	return cpe
}
