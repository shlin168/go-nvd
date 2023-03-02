package schema

import (
	"time"
)

// MitreData is the data feed structure provided from https://nvd.nist.gov/vuln/data-feeds
// Which is going to retire in late 2023. While it is needed to import stale CVE records
//
// Schema: https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
type MitreData struct {
	Timestamp    string         `json:"CVE_data_timestamp"` // "2022-12-25T06:00Z"
	NumberOfCVEs string         `json:"CVE_data_numberOfCVEs"`
	Items        []MitreCveItem `json:"CVE_Items"`
}

// NodeWChild is the recursive structure to store configuration which maps cpe to cve
// It is used only in mitre, and nvd has removed the recursive part
type NodeWChild struct {
	Operator string       `json:"operator"` // "AND", "OR"
	Children []NodeWChild `json:"children"`
	CpeMatch []struct {
		Vulnerable            bool   `json:"vulnerable"`
		Criteria              string `json:"cpe23Uri"` // cpe2.3
		CPEV22                string `json:"cpe22Uri"` // cpe2.2
		VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
		VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
		VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
		VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	} `json:"cpe_match"`
}

// MitreCVSSV2 is the CVSS V2 score structure
type MitreCVSSV2 struct {
	CvssData                CVSSV2Data `json:"cvssV2"`
	BaseSeverity            string     `json:"baseSeverity"`
	ExploitabilityScore     float64    `json:"exploitabilityScore"`
	ImpactScore             float64    `json:"impactScore"`
	AcInsufInfo             bool       `json:"acInsufInfo"`
	ObtainAllPrivilege      bool       `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool       `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool       `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool       `json:"userInteractionRequired"`
}

// MitreCVSSV3 is the CVSS V3 score structure which includes V3.0 and V3.1
type MitreCVSSV3 struct {
	CvssData            CVSSV3Data `json:"cvssV3"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`
}

// MitreCveItem is the unit of each CVE
// In NVD, 'configurations' and 'impact' are also moved into 'cve'
type MitreCveItem struct {
	Cve    MitreCve `json:"cve"`
	Config struct {
		Nodes []NodeWChild `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		CvssMetricV3 MitreCVSSV3 `json:"baseMetricV3"`
		CvssMetricV2 MitreCVSSV2 `json:"baseMetricV2"`
	} `json:"impact"`
	Published    string `json:"publishedDate"`    // format: "2022-12-25T05:15Z"
	LastModified string `json:"lastModifiedDate"` // format: "2022-12-25T05:15Z"
}

// MitreCve is the cve part of MitreCveItem
type MitreCve struct {
	// DataType is the type of data, while most of them is "cve"
	DataType string `json:"data_type"`

	// CVEDataMeta is the meta for CVE, includes ID and sources
	CVEDataMeta struct {
		// ID is the ID of CVE, E.g., CVE-2022-45197
		ID string `json:"ID"`
		// SourceIdentifier is the source name, while most of them is 'cve@mitre.org'
		SourceIdentifier string `json:"ASSIGNER"` // maps to sourceIdentifier
	} `json:"CVE_data_meta"`

	// Description describes the vulnerability with sufficient detail
	Description struct {
		Data []Description `json:"description_data"`
	} `json:"description"`

	// Weaknesses is Common Weakness Enumeration (CWE), which was created to identify
	// common software security weaknesses.
	Weaknesses struct {
		Data []struct {
			Descr []Description `json:"description"` // E.g., value: "CWE-668"
		} `json:"problemtype_data"`
	} `json:"problemtype"`

	// References are supplemental information relevant to the vulnerability
	References struct {
		Data []Reference `json:"reference_data"`
	} `json:"references"`
}

// cvtNVDTimeFormat converts time format from old to new.
// E.g., 2022-12-25T05:15Z -> 2022-08-11T15:15:10.593
func cvtNVDTimeFormat(oldTime string) (string, error) {
	t, err := time.Parse("2006-01-02T15:04Z", oldTime)
	if err != nil {
		return "", err
	}
	return t.Format("2006-01-02T15:04:05.000"), nil
}

// ToAPIStruct converts stale format to new API reponse format
// while some of the fields is filled with fixed value since the old format does not provide them
func (m MitreCveItem) ToAPIStruct() (*CveItem, error) {
	newPublished, err := cvtNVDTimeFormat(m.Published)
	if err != nil {
		return nil, err
	}
	newLastModified, err := cvtNVDTimeFormat(m.LastModified)
	if err != nil {
		return nil, err
	}

	cve := &Cve{
		CVEID:            m.Cve.CVEDataMeta.ID,
		SourceIdentifier: m.Cve.CVEDataMeta.SourceIdentifier,
		Published:        newPublished,
		LastModified:     newLastModified,
		VulnStatus:       "Analyzed",
		Descriptions:     m.Cve.Description.Data,
		References:       m.Cve.References.Data,
	}

	if len(m.Cve.Weaknesses.Data) > 0 {
		var dscrs []Description
		for _, d := range m.Cve.Weaknesses.Data {
			dscrs = append(dscrs, d.Descr...)
		}
		cve.Weaknesses = append(cve.Weaknesses, Weaknesses{
			Source:      "mitre",
			Type:        "Primary",
			Description: dscrs,
		})
	}

	if len(m.Impact.CvssMetricV2.CvssData.Version) > 0 {
		v2 := CVSSV2{
			Source:                  "mitre",
			Type:                    "Primary",
			CvssData:                m.Impact.CvssMetricV2.CvssData,
			BaseSeverity:            m.Impact.CvssMetricV2.BaseSeverity,
			ExploitabilityScore:     m.Impact.CvssMetricV2.ExploitabilityScore,
			ImpactScore:             m.Impact.CvssMetricV2.ImpactScore,
			AcInsufInfo:             m.Impact.CvssMetricV2.AcInsufInfo,
			ObtainAllPrivilege:      m.Impact.CvssMetricV2.ObtainAllPrivilege,
			ObtainUserPrivilege:     m.Impact.CvssMetricV2.ObtainUserPrivilege,
			ObtainOtherPrivilege:    m.Impact.CvssMetricV2.ObtainOtherPrivilege,
			UserInteractionRequired: m.Impact.CvssMetricV2.UserInteractionRequired,
		}
		// old records do not provide BaseSeverity for CVSS V2, while it can be counted from BaseScore
		if len(v2.BaseSeverity) == 0 {
			score := m.Impact.CvssMetricV2.CvssData.BaseScore
			if score < 4 {
				v2.BaseSeverity = "LOW"
			} else if score < 7 {
				v2.BaseSeverity = "MEDIUM"
			} else {
				v2.BaseSeverity = "HIGH"
			}
		}
		cve.Metrics.CvssMetricV2 = append(cve.Metrics.CvssMetricV2, v2)
	}

	if len(m.Impact.CvssMetricV3.CvssData.Version) > 0 {
		cvssv3Data := CVSSV3{
			Source:              "mitre",
			Type:                "Primary",
			CvssData:            m.Impact.CvssMetricV3.CvssData,
			ExploitabilityScore: m.Impact.CvssMetricV3.ExploitabilityScore,
			ImpactScore:         m.Impact.CvssMetricV3.ImpactScore,
		}
		switch m.Impact.CvssMetricV3.CvssData.Version {
		case "3.0":
			cve.Metrics.CvssMetricV30 = append(cve.Metrics.CvssMetricV30, cvssv3Data)
		case "3.1":
			cve.Metrics.CvssMetricV31 = append(cve.Metrics.CvssMetricV31, cvssv3Data)
		}
	}

	// Configuration
	for _, n := range m.Config.Nodes {
		newConfig := Config{}
		if len(n.CpeMatch) > 0 {
			node := Node{Operator: n.Operator}
			for _, cpeMatch := range n.CpeMatch {
				node.CpeMatch = append(node.CpeMatch, CpeMatch{
					Vulnerable:            cpeMatch.Vulnerable,
					Criteria:              cpeMatch.Criteria, // TODO convert from 2.2 if 2.3 is empty
					VersionStartIncluding: cpeMatch.VersionStartIncluding,
					VersionEndIncluding:   cpeMatch.VersionEndIncluding,
					VersionStartExcluding: cpeMatch.VersionStartExcluding,
					VersionEndExcluding:   cpeMatch.VersionEndExcluding,
				})
			}
			newConfig.Nodes = append(newConfig.Nodes, node)
		} else {
			newConfig.Operator = n.Operator
			for _, c := range n.Children {
				node := Node{Operator: c.Operator}
				for _, cpeMatch := range c.CpeMatch {
					node.CpeMatch = append(node.CpeMatch, CpeMatch{
						Vulnerable:            cpeMatch.Vulnerable,
						Criteria:              cpeMatch.Criteria, // TODO convert from 2.2 if 2.3 is empty
						VersionStartIncluding: cpeMatch.VersionStartIncluding,
						VersionEndIncluding:   cpeMatch.VersionEndIncluding,
						VersionStartExcluding: cpeMatch.VersionStartExcluding,
						VersionEndExcluding:   cpeMatch.VersionEndExcluding,
					})
				}
				newConfig.Nodes = append(newConfig.Nodes, node)
			}
		}
		cve.Configurations = append(cve.Configurations, newConfig)
	}

	return &CveItem{Cve: *cve}, nil
}
