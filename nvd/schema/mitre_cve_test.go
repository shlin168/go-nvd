package schema

import (
	"embed"
	"encoding/json"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/*
var testdataDir embed.FS

func TestCVEAPItoStruct(t *testing.T) {
	old, err := testdataDir.ReadFile("testdata/cve_old1.json")
	require.NoError(t, err)

	var m MitreCveItem
	assert.NoError(t, json.Unmarshal(old, &m))
	sort.Slice(m.Cve.References.Data, func(i, j int) bool {
		return m.Cve.References.Data[i].URL < m.Cve.References.Data[j].URL
	})
	sort.Slice(m.Cve.Description.Data, func(i, j int) bool {
		return m.Cve.Description.Data[i].Lang < m.Cve.Description.Data[j].Lang
	})

	new, err := testdataDir.ReadFile("testdata/cve_new1.json")
	require.NoError(t, err)

	var n CveItem
	assert.NoError(t, json.Unmarshal(new, &n))

	// Change output value since some fields only shows in new api json schema
	n.Cve.Published = n.Cve.Published[:17] + "00.000"
	n.Cve.LastModified = n.Cve.LastModified[:17] + "00.000"
	n.Cve.Metrics.CvssMetricV2[0].Source = "mitre"
	n.Cve.Metrics.CvssMetricV31[0].Source = "mitre"
	n.Cve.Weaknesses[0].Source = "mitre"
	for i := range n.Cve.Configurations {
		for j := range n.Cve.Configurations[i].Nodes {
			for k := range n.Cve.Configurations[i].Nodes[j].CpeMatch {
				n.Cve.Configurations[i].Nodes[j].CpeMatch[k].MatchCriteriaID = ""
			}
		}
	}
	for i := range n.Cve.References {
		n.Cve.References[i].Source = ""
	}
	sort.Slice(n.Cve.References, func(i, j int) bool {
		return n.Cve.References[i].URL < n.Cve.References[j].URL
	})
	sort.Slice(n.Cve.Descriptions, func(i, j int) bool {
		return n.Cve.Descriptions[i].Lang < n.Cve.Descriptions[j].Lang
	})
	n.Cve.Descriptions = n.Cve.Descriptions[:1]

	old2New, err := m.ToAPIStruct()
	require.NoError(t, err)
	if diff := cmp.Diff(&n, old2New); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}

	// test case 2
	old, err = testdataDir.ReadFile("testdata/cve_old2.json")
	require.NoError(t, err)

	m = MitreCveItem{}
	assert.NoError(t, json.Unmarshal(old, &m))
	sort.Slice(m.Cve.References.Data, func(i, j int) bool {
		return m.Cve.References.Data[i].URL < m.Cve.References.Data[j].URL
	})
	sort.Slice(m.Cve.Description.Data, func(i, j int) bool {
		return m.Cve.Description.Data[i].Lang < m.Cve.Description.Data[j].Lang
	})

	new, err = testdataDir.ReadFile("testdata/cve_new2.json")
	require.NoError(t, err)

	n = CveItem{}
	assert.NoError(t, json.Unmarshal(new, &n))

	// Change output value since some fields only shows in new api json schema
	n.Cve.Published = n.Cve.Published[:17] + "00.000"
	n.Cve.LastModified = n.Cve.LastModified[:17] + "00.000"
	n.Cve.Metrics.CvssMetricV31[0].Source = "mitre"
	n.Cve.Metrics.CvssMetricV31 = n.Cve.Metrics.CvssMetricV31[:1]
	n.Cve.Weaknesses[0].Source = "mitre"
	for i := range n.Cve.Configurations {
		for j := range n.Cve.Configurations[i].Nodes {
			for k := range n.Cve.Configurations[i].Nodes[j].CpeMatch {
				n.Cve.Configurations[i].Nodes[j].CpeMatch[k].MatchCriteriaID = ""
			}
		}
	}
	for i := range n.Cve.References {
		n.Cve.References[i].Source = ""
	}
	sort.Slice(n.Cve.References, func(i, j int) bool {
		return n.Cve.References[i].URL < n.Cve.References[j].URL
	})
	sort.Slice(n.Cve.Descriptions, func(i, j int) bool {
		return n.Cve.Descriptions[i].Lang < n.Cve.Descriptions[j].Lang
	})

	old2New, err = m.ToAPIStruct()
	require.NoError(t, err)
	if diff := cmp.Diff(&n, old2New); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}
