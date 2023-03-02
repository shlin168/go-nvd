package schema

import (
	"testing"

	"github.com/hashicorp/go-version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCPEParsedMap(t *testing.T) {
	cpe := "cpe:2.3:*:Microsoft"
	cpeParsed := NewCPEParsedMap(cpe)
	assert.Equal(t, "Microsoft", cpeParsed[CPEVendor.String()])
	assert.Equal(t, "*", cpeParsed[CPEPart.String()])
}

func TestVersionInRangeIncluding(t *testing.T) {
	target := "4.5"
	targetVersion, err := version.NewVersion(target)
	require.NoError(t, err)

	// version in range
	for _, pair := range [][2]string{
		{"2.0", "6.0"},
		{"", "6.0"}, // empty means no bound
		{"", "4.5"}, // value in bound that same as target is counted in range
		{"1.5", ""},
		{"1.5.1", "2.0.beta"}, // 2.0.beta is invalid version string, not setting upperbound
		{"1.0", "6.0.2+meta"}, // 6.0.2+meta = 6.0.2
		{"", ""},
		{"3", ""},
	} {
		start := versionBound{val: pair[0], include: true}
		end := versionBound{val: pair[1], include: true}
		if !VersionInRange(start, end, targetVersion) {
			t.Errorf("%s should be in range: %s, %s", targetVersion, pair[0], pair[1])
		}
	}

	// version not in range
	for _, pair := range [][2]string{
		{"2.0.1", "3.5.1"},
		{"1.0.2", "3.0.1-beta"}, // 3.0.1-beta = 3.0.1
		{"", "2"},
	} {
		start := versionBound{val: pair[0], include: true}
		end := versionBound{val: pair[1], include: true}
		if VersionInRange(start, end, targetVersion) {
			t.Errorf("%s should not be in range: %s, %s", targetVersion, pair[0], pair[1])
		}
	}
}

func TestVersionInRangeExcluding(t *testing.T) {
	target := "4.5"
	targetVersion, err := version.NewVersion(target)
	require.NoError(t, err)

	// version in exclude range
	for _, pair := range [][2]string{
		{"2.0", "6.0"},
		{"", "4.6"},           // if another bound is empty, then only check if it's equal
		{"4.2", ""},           // if another bound is empty, then only check if it's equal
		{"1.0", "6.0.2+meta"}, // 6.0.2+meta = 6.0.2
		{"1.0", "6.0_1"},      // 6.0_1 is not valid version string, only check if version greater than 1.0
		{"", ""},
	} {
		start := versionBound{val: pair[0], include: false}
		end := versionBound{val: pair[1], include: false}
		if !VersionInRange(start, end, targetVersion) {
			t.Errorf("%s should be in range: %s, %s", targetVersion, pair[0], pair[1])
		}
	}

	// version not in exclude range
	for _, pair := range [][2]string{
		{"1.0", "4.3"},
		{"", "2.3"}, // if another bound is empty, then only check if it's equal
		{"6", ""},   // if another bound is empty, then only check if it's equal
	} {
		start := versionBound{val: pair[0], include: false}
		end := versionBound{val: pair[1], include: false}
		if VersionInRange(start, end, targetVersion) {
			t.Errorf("%s should not be in range: %s, %s", targetVersion, pair[0], pair[1])
		}
	}
}

func TestIsOthersMatch(t *testing.T) {
	// test for one part: update, since all the parts after version have the same matching logic
	for _, tcase := range []struct {
		cpeToMatch string
		query      string
		expMatch   bool
	}{
		{cpeToMatch: "*", query: "stable", expMatch: true},
		{cpeToMatch: "-", query: "stable", expMatch: false},
		{cpeToMatch: "stable", query: "stable", expMatch: true},
		{cpeToMatch: "releases", query: "stable", expMatch: false},
		{cpeToMatch: "stable", query: "*", expMatch: true},
		{cpeToMatch: "stable", query: "-", expMatch: false},
	} {
		parsed := CPEParsed{Parsed: map[string]string{CPEUpdate.String(): tcase.cpeToMatch}}
		qParsed := CPEParsed{Parsed: map[string]string{CPEUpdate.String(): tcase.query}}
		if parsed.IsOthersMatch(qParsed) != tcase.expMatch {
			t.Errorf("when query with '%s', match item with update='%s' should be %t",
				tcase.query, tcase.cpeToMatch, tcase.expMatch)
		}
	}

	query := "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:macos:*:*"
	q := NewCPEParsed(query)
	for _, tcase := range []struct {
		qCpeName string
		expMatch bool
	}{
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:macos:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:stable:*:*:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:-:*:*:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:en:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:mac_os:*:*", expMatch: false},
	} {
		p := NewCPEParsed(tcase.qCpeName)
		if p.IsOthersMatch(*q) != tcase.expMatch {
			t.Errorf("when query with '%s', match item with '%s' should be %t",
				tcase.qCpeName, query, tcase.expMatch)
		}
	}

	query = "cpe:2.3:a:trendmicro:antivirus:9.0:stable:*:*:*:macos:*:*"
	q = NewCPEParsed(query)
	for _, tcase := range []struct {
		qCpeName string
		expMatch bool
	}{
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:macos:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:stable:*:*:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:release:*:*:*:*:*:*", expMatch: false},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:-:*:*:*:*:*:*", expMatch: false},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:en:*:*:*:*", expMatch: true},
		{qCpeName: "cpe:2.3:a:trendmicro:antivirus:9.0:*:*:*:*:mac_os:*:*", expMatch: false},
	} {
		p := NewCPEParsed(tcase.qCpeName)
		if p.IsOthersMatch(*q) != tcase.expMatch {
			t.Errorf("when query with '%s', match item with '%s' should be %t",
				tcase.qCpeName, query, tcase.expMatch)
		}
	}
}

func TestIsVersionMatch(t *testing.T) {
	criteriaVer := "cpe:2.3:o:freebsd:freebsd:4.5:*:*:*:*:*:*:*"
	criteriaAll := "cpe:2.3:o:freebsd:freebsd:*:*:*:*:*:*:*:*"
	criteriaUnknown := "cpe:2.3:o:freebsd:freebsd:-:*:*:*:*:*:*:*"

	for _, tcase := range []struct {
		cpeToMatch CpeMatch
		queryVer   string
		expMatch   bool
	}{
		{queryVer: "*", cpeToMatch: CpeMatch{Criteria: criteriaVer}, expMatch: false},
		{queryVer: "-", cpeToMatch: CpeMatch{Criteria: criteriaVer}, expMatch: false},
		{queryVer: "4.5", cpeToMatch: CpeMatch{Criteria: criteriaVer}, expMatch: true},
		{queryVer: "4.5.2", cpeToMatch: CpeMatch{Criteria: criteriaVer}, expMatch: false},

		{queryVer: "4.5", cpeToMatch: CpeMatch{Criteria: criteriaAll, VersionStartIncluding: "2.0"}, expMatch: true},
		{queryVer: "4.5", cpeToMatch: CpeMatch{Criteria: criteriaAll, VersionEndIncluding: "2.0"}, expMatch: false},
		{queryVer: "-", cpeToMatch: CpeMatch{Criteria: criteriaAll}, expMatch: true},

		{queryVer: "4.5", cpeToMatch: CpeMatch{Criteria: criteriaUnknown}, expMatch: false},
		{queryVer: "-", cpeToMatch: CpeMatch{Criteria: criteriaUnknown}, expMatch: true},
		{queryVer: "*", cpeToMatch: CpeMatch{Criteria: criteriaUnknown}, expMatch: true},
	} {

		if tcase.cpeToMatch.IsVersionMatch(tcase.queryVer) != tcase.expMatch {
			t.Errorf("when query with cpename: '%s' match item with version='%s' and cpeMatch: %+v should be %t",
				tcase.queryVer, tcase.cpeToMatch.Criteria, tcase.cpeToMatch, tcase.expMatch)
		}
	}
}
