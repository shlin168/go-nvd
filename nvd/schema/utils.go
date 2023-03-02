package schema

import (
	"strings"

	"github.com/hashicorp/go-version"
)

const (
	// NVDOutTimeFormat is the time format for NVD API
	NVDOutTimeFormat = "2006-01-02T15:04:05.000"
)

type CPEField int

const (
	CPEPart CPEField = iota + 2
	CPEVendor
	CPEProduct
	CPEVersion
	CPEUpdate
	CPEEdition
	CPELang
	CPESWEdition
	CPETargetSW
	CPETargetHW
	CPEOther
)

var CPEFields = []CPEField{
	CPEPart, CPEVendor, CPEProduct, CPEVersion, CPEUpdate,
	CPEEdition, CPELang, CPESWEdition, CPETargetSW, CPETargetHW,
	CPEOther,
}

func (f CPEField) String() string {
	switch f {
	case CPEPart:
		return "part"
	case CPEVendor:
		return "vendor"
	case CPEProduct:
		return "product"
	case CPEVersion:
		return "version"
	case CPEUpdate:
		return "update"
	case CPEEdition:
		return "edition"
	case CPELang:
		return "lang"
	case CPESWEdition:
		return "sw_edition"
	case CPETargetSW:
		return "target_sw"
	case CPETargetHW:
		return "target_hw"
	case CPEOther:
		return "others"
	default:
		return ""
	}
}

// CPEParsed is the structure to store value parsed from CPE 2.3 string. The format is as below:
//
//	cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
type CPEParsed struct {
	// Ori is the original cpe string
	Ori string

	// Parsed is the map to store all parts in cpeName
	Parsed CPEParsedMap

	// PrefixToProduct is the prefix to product
	// E.g., prefix of "cpe:2.3:o:freebsd:freebsd:4.4:*:*:*:*:*:*:*" is "cpe:2.3:o:freebsd:freebsd"
	PrefixToProduct string
}

type CPEParsedMap map[string]string

// NewCPEParsed parses FULL cpeName to struct
func NewCPEParsed(cpeName string) *CPEParsed {
	if !strings.HasPrefix(cpeName, "cpe:2.3:") || strings.Count(cpeName, ":") != int(CPEOther) {
		return nil
	}
	cpeList := strings.Split(cpeName, ":")
	parsed := &CPEParsed{
		Ori:             cpeName,
		PrefixToProduct: strings.Join(cpeList[:CPEVersion], ":"),
	}
	parsed.Parsed = NewCPEParsedMap(cpeName)
	return parsed
}

func (p CPEParsed) Get(fnum CPEField) string {
	if len(p.Parsed) > 0 {
		return p.Parsed[fnum.String()]
	}
	return ""
}

// GetLastSpecificIndex gets the last item that is non "*" or "-"
//
// Usage:
//
//	// LastSpecificIndex = CPEVersion = 5
//	fmt.Println(GetLastSpecificIndex("cpe:2.3:o:freebsd:freebsd:4.4:*:*:*:*:*:*:*"))  // 5
func GetLastSpecificIndex(cpeName string) int {
	cpeList := strings.Split(cpeName, ":")
	for i := len(cpeList) - 1; i >= 0; i-- {
		if IsSpecific(cpeList[i]) {
			return i
		}
	}
	return -1
}

// NewCPEParsedMap parses full or partial cpeName to struct
func NewCPEParsedMap(cpeName string) CPEParsedMap {
	if !strings.HasPrefix(cpeName, "cpe:2.3:") || strings.Count(cpeName, ":") < int(CPEVendor) {
		return nil
	}
	parsedMap := make(map[string]string)
	for i, p := range strings.Split(cpeName, ":")[CPEPart:] {
		fieldNum := CPEField(i + int(CPEPart))
		if fieldName := fieldNum.String(); len(fieldName) > 0 {
			parsedMap[fieldName] = p
		}
	}
	return parsedMap
}

func getProductPrefix(cpeName string) string {
	cpeList := strings.Split(cpeName, ":")
	if len(cpeList) < 6 {
		return ""
	}
	return strings.Join(cpeList[:5], ":")
}

// IsAll return if value is represents 'all' in query
func IsAll(val string) bool {
	return val == "*"
}

// IsUnknown return if value is represents 'unknown' in query
func IsUnknown(val string) bool {
	return val == "-"
}

// IsSpecific return if value is represents specific version in query
func IsSpecific(val string) bool {
	return !(IsAll(val) || IsUnknown(val))
}

// adjustVersion try to fix verison that is not follow common version format, E.g., 0.4_1
//
// version format: https://semver.org
func adjustVersion(rawVal string) string {
	return strings.ReplaceAll(rawVal, "_", ".")
}

type versionBound struct {
	val     string
	include bool
}

// VersionInRange checks whether version is in 'versionStart(Including|Excluding)' and 'versionEnd(Including|Excluding)'
func VersionInRange(start, end versionBound, v *version.Version) bool {
	var vStart, vEnd *version.Version
	vStart, _ = version.NewVersion(adjustVersion(start.val))
	vEnd, _ = version.NewVersion(adjustVersion(end.val))

	// If both 'versionStart(Including|Excluding)' and 'versionEnd(Including|Excluding)' is NOT set, then return true
	if vStart == nil && vEnd == nil {
		return true
	}

	startMatch, endMatch := true, true

	// If contains 'versionEnd(Including|Excluding), check if input < upper bound
	if vEnd != nil {
		if end.include {
			endMatch = v.LessThanOrEqual(vEnd)
		} else {
			endMatch = v.LessThan(vEnd)
		}
	}

	// If contains 'versionStart(Including|Excluding)', check if input > lower bound
	if vStart != nil {
		if start.include {
			startMatch = v.GreaterThanOrEqual(vStart)
		} else {
			startMatch = v.GreaterThan(vStart)
		}
	}

	return startMatch && endMatch
}

// IsVersionMatch match criteria (CPE Name 2.3) with query version
func (cpeToMatch CpeMatch) IsVersionMatch(qryVerStr string) bool {
	parsed := NewCPEParsed(cpeToMatch.Criteria)
	if parsed == nil {
		return false
	}

	// criteria contains version, only matches when they are the same
	pv := parsed.Get(CPEVersion)
	if IsSpecific(pv) {
		if pv == qryVerStr {
			return true
		}
		// try to match when query version = 6.5.0, and cpe match criteria = 6.5
		// they are actually same version while the strings are not exactly equal
		// Note: while it might cause FP when partial version can not fill with 0
		// User might not means 6.5.0 when they query with 6.5
		qV, _ := version.NewVersion(qryVerStr)
		pV, _ := version.NewVersion(pv)
		if qV != nil && pV != nil && qV.Equal(pV) {
			return true
		}
	}

	// criteria="*"
	if IsAll(pv) {
		if !IsSpecific(qryVerStr) { // if query with "*" or "-", matches when criteria="*"
			return true
		}

		// query with version, then check Version Including and Excluding
		qV, err := version.NewVersion(qryVerStr)
		if err != nil {
			return false
		}

		var start, end versionBound // don't use pointer since function 'VersionInRange' handles struct with zero value

		// setting start bound for version
		// Including and Excluding is expected to be both empty or only one that contains value, if there's item that contains both
		// Then need to check how NVD handle that
		if len(cpeToMatch.VersionStartIncluding) > 0 {
			start = versionBound{val: cpeToMatch.VersionStartIncluding, include: true}
		}
		if len(cpeToMatch.VersionStartExcluding) > 0 {
			start = versionBound{val: cpeToMatch.VersionStartExcluding, include: false}
		}

		// setting end bound for version
		// Including and Excluding is expected to be both empty or only one that contains value, if there's item that contains both
		// Then need to check how NVD handle that
		if len(cpeToMatch.VersionEndIncluding) > 0 {
			end = versionBound{val: cpeToMatch.VersionEndIncluding, include: true}
		}
		if len(cpeToMatch.VersionEndExcluding) > 0 {
			end = versionBound{val: cpeToMatch.VersionEndExcluding, include: false}
		}

		return VersionInRange(start, end, qV)
	}

	// criteria="-"
	if IsUnknown(pv) && !IsSpecific(qryVerStr) { // matches when user query with "*" or "-"
		return true
	}

	return false
}

// IsOthersMatch match criteria (CPE Name 2.3) with update:edition:language:sw_edition:target_sw:target_hw:other
func (candidate CPEParsed) IsOthersMatch(qParsed CPEParsed) bool {
	for _, part := range CPEFields[4:] {
		cPart := candidate.Get(part)
		qPart := qParsed.Get(part)
		if matches := IsAll(cPart) || IsAll(qPart) || (IsSpecific(qPart) && qPart == cPart); !matches {
			return false
		}
	}
	return true
}
