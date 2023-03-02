package server

const (
	APIGroupNVD = "/nvd"

	APIPathGetCVE = "/cve"
	APIPathGetCPE = "/cpe"

	APIPathReady = "/readiness"

	// Status... are variables that shows the status for API
	// Since api returns 200 for both 'found' and 'not_found' instead of 404,
	// it should be another field to inform the status from DB
	StatusFound    = "found"
	StatusNotFound = "not_found"
	StatusError    = "error"

	// Qs... are keys of query string that are valid for API
	QsCveId          = "cveId"
	QsCpeName        = "cpeName"
	QsCpeMatchStr    = "cpeMatchString"
	QsKeyword        = "keywordSearch"
	QsKeywordExact   = "keywordExactMatch"
	QsStartIndex     = "startIndex"
	QsResultsPerPage = "resultsPerPage"
)

var (
	// CVEQSKeys is the keys of query string. It's expected to provide one of them for CVE API
	CVEQSKeys = []string{QsCveId, QsCpeName, QsKeyword}

	// CPEQSKeys is the keys of query string. It's expected to provide one of them for CPE API
	CPEQSKeys = []string{QsCpeMatchStr, QsCpeName, QsKeyword}
)
