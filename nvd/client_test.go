package nvd

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-nvd/nvd/schema"
)

//go:embed schema/testdata/cve_mock.json
var mockCVEContent []byte

//go:embed schema/testdata/cve_mock_multi.json
var mockCVEMultiContent []byte

//go:embed schema/testdata/cpe_mock.json
var mockCPEContent []byte

//go:embed schema/testdata/cpe_mock_multi.json
var mockCPEMultiContent []byte

func TestNVDClient(t *testing.T) {
	cli, err := NewClient()
	require.NoError(t, err)
	assert.Equal(t, retryablehttp.NewClient().HTTPClient.Timeout, cli.cli.HTTPClient.Timeout)
	assert.Equal(t, NVDBaseCVEURL, cli.cveQuerier.url)
	assert.Equal(t, NVDBaseCPEURL, cli.cpeQuerier.url)
	assert.Equal(t, DefaultWaitInterval, cli.cveQuerier.waitEachReq)
	assert.Equal(t, DefaultWaitInterval, cli.cpeQuerier.waitEachReq)
	assert.NotNil(t, cli.cveQuerier.logger)
	assert.NotNil(t, cli.cpeQuerier.logger)

	// Check if init with options change the config
	cli, err = NewClient(
		Timeout(3*time.Second),
		Retries(2),
	)
	require.NoError(t, err)
	assert.Equal(t, 3*time.Second, cli.cli.HTTPClient.Timeout)
	assert.Equal(t, 2, cli.cli.RetryMax)

	// Check invalid config raise error
	for _, opt := range []Option{
		Timeout(-1),
		Retries(-1),
	} {
		_, err := NewClient(opt)
		assert.Error(t, err)
	}
}

func TestNVDClientGetCVEDataInLastModRange(t *testing.T) {
	var queryCnt int
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCnt++
		if r.URL.Path != "/rest/json/cves/2.0" {
			http.Error(w, "path is wrong", http.StatusNotFound)
		}
		sdate := r.URL.Query().Get("lastModStartDate")
		edate := r.URL.Query().Get("lastModEndDate")
		if sdate == "2022-12-01T00:00:00.000" && edate == "2022-12-10T00:00:00.000" {
			w.Header().Set("Content-Type", "application/json; charset=utf8")
			w.Write(mockCVEContent)
			return
		}

		if sdate == "2022-12-01T00:00:00.000" && edate == "2022-12-31T00:00:00.000" {
			w.Header().Set("Content-Type", "application/json; charset=utf8")
			var rsp schema.APIResp[schema.CveItem]
			if err := json.Unmarshal(mockCVEMultiContent, &rsp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			startIndexStr := r.URL.Query().Get("startIndex")
			startIndex, _ := strconv.Atoi(startIndexStr)
			rsp.Items = rsp.Items[startIndex : startIndex+rsp.ResultsPerPage]
			rsp.StartIndex = startIndex
			out, _ := json.Marshal(rsp)
			w.Write(out)
		}
		if sdate == "2022-12-15T00:00:00.000" {
			http.Error(w, "error", http.StatusInternalServerError)
		}
	}))
	defer mockSrv.Close()

	url, _ := url.JoinPath(mockSrv.URL, "rest/json/cves/2.0")
	cli, err := NewClient(BaseCVEURL(url), Retries(0), Wait(100*time.Millisecond))
	require.NoError(t, err)

	// query 1 time to get all result
	rsp, err := cli.GetCVEsInRange("2022-12-01", "2022-12-10")
	require.NoError(t, err)
	assert.Equal(t, 1, rsp.TotalResults)
	assert.Equal(t, "CVE-2006-3240", rsp.Items[0].Cve.CVEID)
	assert.Equal(t, 1, queryCnt)
	queryCnt = 0

	// query 3 times to get all result
	rsp, err = cli.GetCVEsInRange("2022-12-01", "2022-12-31")
	require.NoError(t, err)
	require.Equal(t, 3, rsp.TotalResults)
	assert.Equal(t, 3, len(rsp.Items))
	assert.Equal(t, "CVE-2021-38540", rsp.Items[0].Cve.CVEID)
	assert.Equal(t, 3, queryCnt)

	// get error response from server
	rsp, err = cli.GetCVEsInRange("2022-12-15", "2022-12-31")
	require.Error(t, err)
	assert.Empty(t, rsp)
}

func TestNVDClientGetCPEDataInLastModRange(t *testing.T) {
	var queryCnt int
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCnt++
		if r.URL.Path != "/rest/json/cpes/2.0" {
			http.Error(w, "path is wrong", http.StatusNotFound)
		}
		sdate := r.URL.Query().Get("lastModStartDate")
		edate := r.URL.Query().Get("lastModEndDate")
		if sdate == "2022-12-01T00:00:00.000" && edate == "2022-12-10T00:00:00.000" {
			w.Header().Set("Content-Type", "application/json; charset=utf8")
			w.Write(mockCPEContent)
			return
		}

		if sdate == "2022-12-01T00:00:00.000" && edate == "2022-12-31T00:00:00.000" {
			w.Header().Set("Content-Type", "application/json; charset=utf8")
			var rsp schema.APIResp[schema.CpeItem]
			if err := json.Unmarshal(mockCPEMultiContent, &rsp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			startIndexStr := r.URL.Query().Get("startIndex")
			startIndex, _ := strconv.Atoi(startIndexStr)
			rsp.Items = rsp.Items[startIndex : startIndex+rsp.ResultsPerPage]
			rsp.StartIndex = startIndex
			out, _ := json.Marshal(rsp)
			w.Write(out)
		}
		if sdate == "2022-12-15T00:00:00.000" {
			http.Error(w, "error", http.StatusInternalServerError)
		}
	}))
	defer mockSrv.Close()

	url, _ := url.JoinPath(mockSrv.URL, "rest/json/cpes/2.0")
	cli, err := NewClient(BaseCPEURL(url), Retries(0), Wait(100*time.Millisecond))
	require.NoError(t, err)

	// query 1 time to get all result
	rsp, err := cli.GetCPEsInRange("2022-12-01", "2022-12-10")
	require.NoError(t, err)
	assert.Equal(t, 1, rsp.TotalResults)
	assert.Equal(t, "cpe:2.3:a:netsarang:xshell:7:-:*:*:*:*:*:*", rsp.Items[0].Cpe.Name)
	assert.Equal(t, 1, queryCnt)
	queryCnt = 0

	// query 3 times to get all result
	rsp, err = cli.GetCPEsInRange("2022-12-01", "2022-12-31")
	require.NoError(t, err)
	assert.Equal(t, 3, rsp.TotalResults)
	assert.Equal(t, 3, len(rsp.Items))
	assert.Equal(t, "cpe:2.3:a:microsoft:office:2021:*:*:*:ltsc:*:x64:*", rsp.Items[0].Cpe.Name)
	assert.Equal(t, 3, queryCnt)

	// get error response from server
	rsp, err = cli.GetCPEsInRange("2022-12-15", "2022-12-31")
	require.Error(t, err)
	assert.Empty(t, rsp)
}
