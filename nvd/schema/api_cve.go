package schema

import (
	"regexp"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

/*
*	NVD Vulnerabilities Detail Pages
*   https://nvd.nist.gov/vuln/vulnerability-detail-pages

*  CVSS: The Common Vulnerability Scoring System (CVSS) is a method used to supply a qualitative measure
		 of severity. CVSS is not a measure of risk
*/

var (
	cvePtn, _ = regexp.Compile(`^CVE-[\d]{4}-[\d]{4,}$`)
)

func IsValidCVE(cve string) bool {
	return cvePtn.MatchString(cve)
}

// Description is plain language field that should describe the vulnerability with sufficient detail
// as to demonstrate that the vulnerability is unique
type Description struct {
	Lang  string `json:"lang" bson:"lang"`
	Value string `json:"value" bson:"value"`
}

// CVSSV2Data is data of CVSSV2
type CVSSV2Data struct {
	Version               string  `json:"version" bson:"version"` // "2.0"
	VectorString          string  `json:"vectorString" bson:"vectorString"`
	AccessVector          string  `json:"accessVector" bson:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity" bson:"accessComplexity"`
	Authentication        string  `json:"authentication" bson:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact" bson:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact" bson:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact" bson:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore" bson:"baseScore"`
}

// CVSSV2 stores V2 of CVSS which is no longer generates new data as of July 13th, 2022
type CVSSV2 struct {
	Source                  string     `json:"source" bson:"source"`
	Type                    string     `json:"type" bson:"type"`
	CvssData                CVSSV2Data `json:"cvssData" bson:"cvssData"`
	BaseSeverity            string     `json:"baseSeverity" bson:"baseSeverity"`
	ExploitabilityScore     float64    `json:"exploitabilityScore" bson:"exploitabilityScore"`
	ImpactScore             float64    `json:"impactScore" bson:"impactScore"`
	AcInsufInfo             bool       `json:"acInsufInfo" bson:"acInsufInfo"`
	ObtainAllPrivilege      bool       `json:"obtainAllPrivilege" bson:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool       `json:"obtainUserPrivilege" bson:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool       `json:"obtainOtherPrivilege" bson:"obtainOtherPrivilege"`
	UserInteractionRequired bool       `json:"userInteractionRequired" bson:"userInteractionRequired"`
}

// CVSSV3Data is data of CVSSV3
type CVSSV3Data struct {
	Version               string  `json:"version" bson:"version"` // "3.0", "3.1"
	VectorString          string  `json:"vectorString" bson:"vectorString"`
	AttackVector          string  `json:"attackVector" bson:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity" bson:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired" bson:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction" bson:"userInteraction"`
	Scope                 string  `json:"scope" bson:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact" bson:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact" bson:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact" bson:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore" bson:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity" bson:"baseSeverity"`
}

// CVSSV3 stores V3.0 and V3.1 of CVSS
type CVSSV3 struct {
	Source              string     `json:"source" bson:"source"`
	Type                string     `json:"type" bson:"type"`
	CvssData            CVSSV3Data `json:"cvssData" bson:"cvssData"`
	ExploitabilityScore float64    `json:"exploitabilityScore" bson:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore" bson:"impactScore"`
}

// CpeMatch describes how this cpe (Criteria) matches to the CVE
type CpeMatch struct {
	Vulnerable bool `json:"vulnerable" bson:"vulnerable"`

	// Criteria is cpe 2.3 format string as one of the condition that might contains this CVE
	// E.g., cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*
	Criteria string `json:"criteria" bson:"criteria"` // cpe2.3

	// CriteriaProductPrefix is generated from field 'Criteria', which is not in either NVD or Mitre response
	// We generate this field as one of the index which benefits the performance when query with cpe name
	//
	// For example, when Criteria is "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", then
	// CriteriaProductPrefix will be "cpe:2.3:a:apache:http_server".
	//
	// Since user can query with many kinds of version formats (E.g., '*', '-', '2.0', '3', ...),
	// When trying to match CVEs from CPE, we search with ProductPrefix first, then filter the result before return
	CriteriaProductPrefix string `json:"-" bson:"criteriaProductPrefix"`

	// MatchCriteriaID is the unique ID in NVD response which is used as query parameter for other API.
	// Mitre does not contains this field
	MatchCriteriaID string `json:"matchCriteriaId" bson:"matchCriteriaId"`

	// When Criteria does not specify the version, the range of the version is given by below 4 fields
	VersionStartIncluding string `json:"versionStartIncluding,omitempty" bson:"versionStartIncluding"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty" bson:"versionEndIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty" bson:"versionStartExcluding"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty" bson:"versionEndExcluding"`
}

// Weaknesses is Common Weakness Enumeration (CWE), which was created to identify
// common software security weaknesses.
type Weaknesses struct {
	Source      string        `json:"source" bson:"source"`
	Type        string        `json:"type" bson:"type"`
	Description []Description `json:"description" bson:"description"` // E.g., value: "CWE-668"
}

// References are supplemental information relevant to the vulnerability
type Reference struct {
	URL    string   `json:"url" bson:"url"`
	Source string   `json:"source" bson:"source"` // vulnerability@ncsc.ch. Mitre does not contains this field (there's refsource but not the same)
	Tags   []string `json:"tags,omitempty" bson:"tags,omitempty"`
}

// Node is the unit of configuration to decide the conditions how cpe match to this cve
type Node struct {
	Operator string     `json:"operator" bson:"operator"` // "AND", "OR"
	Negate   bool       `json:"negate" bson:"negate"`
	CpeMatch []CpeMatch `json:"cpeMatch" bson:"cpeMatch"`
}

// Config is a container that holds a set of nodes which then contain CPE Name Match Criteria
type Config struct {
	Operator string `json:"operator,omitempty" bson:"operator,omitempty"` // "AND", "OR"
	Negate   bool   `json:"negate,omitempty" bson:"negate,omitempty"`
	Nodes    []Node `json:"nodes" bson:"nodes"`
}

// CveItem is the unit of one CVE record in NVD
type CveItem struct {
	Cve Cve `json:"cve"`
}

// Metrics is a collection of multiple version of CVSS scores.
type Metrics struct {
	CvssMetricV31 []CVSSV3 `json:"cvssMetricV31,omitempty" bson:"cvssMetricV31,omitempty"`
	CvssMetricV30 []CVSSV3 `json:"cvssMetricV30,omitempty" bson:"cvssMetricV30,omitempty"`
	CvssMetricV2  []CVSSV2 `json:"cvssMetricV2,omitempty" bson:"cvssMetricV2,omitempty"`
}

// Cve is the cve part of one CVE record, while looks like all the information is stored in cve
// It is also the unit struct for each cve record in db
type Cve struct {
	// Id is the auto generated ID for document DB
	Id *primitive.ObjectID `json:"-" bson:"_id,omitempty"`

	// CVEID is the ID of CVE, E.g., CVE-2022-45197
	CVEID string `json:"id" bson:"cveId"`

	// SourceIdentifier is the source name, values can be 'nvd@nist.gov', 'cve@mitre.org', ...
	SourceIdentifier string `json:"sourceIdentifier" bson:"sourceIdentifier"`

	// Published is the time when this CVE is published.
	// Format: 2022-08-11T15:15:10.593
	Published string `json:"published" bson:"published"`

	// LastModified is the last time this CVE has been modified
	// Format: 2022-08-11T15:15:10.593
	LastModified string `json:"lastModified" bson:"lastModified"`

	// VulnStatus is the new field in NVD to describe the analysis status
	// Value includes: Analyzed, Undergoing Analysis, Modified.
	// All the data from Mitre is given with 'Analyzed'
	VulnStatus string `json:"vulnStatus" bson:"vulnStatus"`

	// Descriptions describe the vulnerability with sufficient detail
	// NVD contains more description than mitre
	Descriptions []Description `json:"descriptions" bson:"descriptions"`

	// Metrics contains multiple version of CVSS scores
	// In NVD, there might be multiple scores with same version which is given from different sources
	// It can be differenciate by Source and Type (Primary, Secondary) fields
	Metrics Metrics `json:"metrics"`

	// Weaknesses is Common Weakness Enumeration (CWE), which was created to identify
	// common software security weaknesses.
	Weaknesses []Weaknesses `json:"weaknesses" bson:"weaknesses"`

	// Configurations is a container that holds a set of nodes which then contain CPE Name Match Criteria
	Configurations []Config `json:"configurations" bson:"configurations"`

	// References are supplemental information relevant to the vulnerability
	References []Reference `json:"references" bson:"references"`
}

// Match checks whether incoming query (cpe) matches this CVE
func (c Cve) Match(qParsed CPEParsed) bool {
	for _, config := range c.Configurations {
		for _, node := range config.Nodes {
			for _, cpematch := range node.CpeMatch {
				if cpematch.Criteria == qParsed.Ori {
					return true
				}
				cpeParsed := NewCPEParsed(cpematch.Criteria)
				if cpeParsed == nil || qParsed.PrefixToProduct != cpeParsed.PrefixToProduct {
					continue
				}
				if cpematch.IsVersionMatch(qParsed.Get(CPEVersion)) &&
					cpeParsed.IsOthersMatch(qParsed) {
					return true
				}
			}
		}
	}
	return false
}

// AddCriteriaProductPrefixs fill value to 'CriteriaProductPrefix' for every CpeMatchItems,
// which should be invoked before upserting data to database (when -db-type=mongo) since
// 'CriteriaProductPrefix' is set as index to enhance the performance when query with CPE name
func (c *Cve) AddCriteriaProductPrefixs() {
	for i, config := range c.Configurations {
		for j, node := range config.Nodes {
			for k, cpematch := range node.CpeMatch {
				c.Configurations[i].Nodes[j].CpeMatch[k].CriteriaProductPrefix =
					getProductPrefix(cpematch.Criteria)
			}
		}
	}
}
