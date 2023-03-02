package schema

import (
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// APIRespItem is the common interface of CVE and CPE
type APIRespItem interface {
	CveItem | CpeItem
}

// APIRespInfo is the common info of API response from NVD's CVE and CPE API
type APIRespInfo struct {
	ResultsPerPage int    `json:"resultsPerPage"`
	StartIndex     int    `json:"startIndex"`
	TotalResults   int    `json:"totalResults"`
	Format         string `json:"format"`
	Version        string `json:"version"`
	Timestamp      string `json:"timestamp"`
}

// APIResp is the response from NVD's CVE and CPE API
// 'Items' stores the list of CVE or CPE
// * CVE with json tag: "vulnerabilities"
// * CPE with json tag: "products"
type APIResp[T APIRespItem] struct {
	APIRespInfo
	Items []T
}

// UnmarshalJSON implements custom json.Unmarshaler for APIResp due to dynamic json tag and type of Items
// To avoid infinite loop, it use temp struct and json.RawMessage to unmarshal 'Items' field
// ref. https://stackoverflow.com/questions/62951510/unmarshal-remaining-json-after-performing-custom-unmarshalling
func (ar *APIResp[T]) UnmarshalJSON(data []byte) error {
	type _APIResp APIResp[T]

	switch any(ar.Items).(type) {
	case []CveItem:
		var temp struct {
			RawItems json.RawMessage `json:"vulnerabilities"`
			_APIResp
		}

		if err := json.Unmarshal(data, &temp); err != nil {
			return err
		}

		*ar = APIResp[T](temp._APIResp)
		return json.Unmarshal([]byte(temp.RawItems), &ar.Items)
	case []CpeItem:
		var temp struct {
			RawItems json.RawMessage `json:"products"`
			_APIResp
		}

		if err := json.Unmarshal(data, &temp); err != nil {
			return err
		}

		*ar = APIResp[T](temp._APIResp)
		return json.Unmarshal([]byte(temp.RawItems), &ar.Items)
	}

	return errors.New("invalid type")
}

// MarshalJSON implements custom json.Marshaler for APIResp due to dynamic json tag and type of Items
func (ar APIResp[T]) MarshalJSON() ([]byte, error) {
	info := APIRespInfo{
		ResultsPerPage: ar.ResultsPerPage,
		StartIndex:     ar.StartIndex,
		TotalResults:   ar.TotalResults,
		Format:         ar.Format,
		Version:        ar.Version,
		Timestamp:      ar.Timestamp,
	}

	switch any(ar.Items).(type) {
	case []CveItem:
		return json.Marshal(&struct {
			APIRespInfo
			Items []T `json:"vulnerabilities"`
		}{
			APIRespInfo: info,
			Items:       ar.Items,
		})
	case []CpeItem:
		return json.Marshal(&struct {
			APIRespInfo
			Items []T `json:"products"`
		}{
			APIRespInfo: info,
			Items:       ar.Items,
		})
	}

	return []byte{}, errors.New("invalid type")
}

// Init set default value for APIResp
func (ar *APIResp[T]) Init() {
	ar.APIRespInfo = APIRespInfo{
		Version:   "2.0",
		Timestamp: time.Now().Format(NVDOutTimeFormat),
	}
	ar.Items = []T{}
	switch any(ar.Items).(type) {
	case []CveItem:
		ar.APIRespInfo.Format = "NVD_CVE"
	case []CpeItem:
		ar.APIRespInfo.Format = "NVD_CPE"
	}
}

func (ar *APIResp[T]) Sort(fn func(i, j int) bool) {
	sort.Slice(ar.Items, fn)
}

func (ar APIResp[T]) IsNotFound() bool {
	return len(ar.Items) == 0
}
