package schema

import (
	_ "embed"
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/cpe-mitre.xml
var mockCPEXMLContent []byte

func TestCPEAPItoStruct(t *testing.T) {
	cpeOld := []byte(`
	<cpe-item name="cpe:/a:compaq:openvms:-">
    	<title xml:lang="en-US">Compaq OpenVMS</title>
    	<cpe-23:cpe23-item name="cpe:2.3:a:compaq:openvms:-:*:*:*:*:*:*:*"/>
	</cpe-item>
	`)

	var m MitreCpe
	require.NoError(t, xml.Unmarshal(cpeOld, &m))
	covertNvdCpe := m.ToAPIStruct()

	cpeNew := []byte(`
	{
		"deprecated": false,
		"cpeName": "cpe:2.3:a:compaq:openvms:-:*:*:*:*:*:*:*",
		"cpeNameId": "61B4C5D9-C242-4229-8725-2336F72E77B5",
		"lastModified": "2007-11-01T16:01:46.530",
		"created": "2007-11-01T16:01:46.530",
		"titles": [
			{
				"title": "Compaq OpenVMS",
				"lang": "en"
			}
		]
	}
	`)
	var n Cpe
	require.NoError(t, json.Unmarshal(cpeNew, &n))

	assert.Equal(t, n.Name, covertNvdCpe.Name)
	assert.Empty(t, covertNvdCpe.LastModified)
	assert.Empty(t, covertNvdCpe.NameID)
	assert.Equal(t, n.Titles[0].Title, covertNvdCpe.Titles[0].Title)
	assert.Equal(t, n.Titles[0].Lang+"-US", covertNvdCpe.Titles[0].Lang)
}

func TestCPEReadFromMitreXML(t *testing.T) {
	var m MitreCpeList
	require.NoError(t, xml.Unmarshal(mockCPEXMLContent, &m))

	assert.Equal(t, 5, len(m.CpeItem))
	assert.Equal(t, "cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~", m.CpeItem[0].Name)
}
