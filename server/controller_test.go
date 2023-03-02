package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-nvd/nvd/schema"
	"github.com/shlin168/go-nvd/server/testutils"
)

func TestHandlerGetCVE(t *testing.T) {
	reg := prometheus.NewRegistry()
	MetricRegisterOn(reg)
	defer MetricUnRegister(reg)

	cpeName := "cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*"
	cveId := "CVE-2006-3240"
	cveKeyword := "dotproject"

	getCvePath := APIGroupNVD + "/v1" + APIPathGetCVE
	for _, mock := range []testutils.Mock{
		{
			ReqPath: getCvePath + "?",
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusBadRequest, code)
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("400", getCvePath)))
			},
		},
		{
			ReqPath: getCvePath + "?cpeName=" + cpeName + "&cveId=" + cveId,
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusBadRequest, code)
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("400", getCvePath)))
			},
		},
		{
			// Found: search by cpe
			ReqPath: getCvePath + "?cpeName=" + cpeName,
			DBMock:  testutils.DBMock{GetCVEByCPEResult: []schema.Cve{{CVEID: cveId}}},
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CveItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 1, result.TotalResults)
				assert.Equal(t, cveId, result.Items[0].Cve.CVEID)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCvePath)))
			},
		},
		{
			// Not found: search by cpe
			ReqPath: getCvePath + "?cpeName=" + cpeName,
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CveItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 0, result.TotalResults)
				assert.Empty(t, result.Items)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusNotFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCvePath)))
			},
		},
		{
			// Error: search by cpe
			ReqPath: getCvePath + "?cpeName=" + cpeName,
			DBMock:  testutils.DBMock{GetNVDError: errors.New("something happened")},
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusInternalServerError, code)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusError)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("500", getCvePath)))
			},
		},
		{
			// Found: search by cve ID
			ReqPath: getCvePath + "?cveId=" + cveId,
			DBMock:  testutils.DBMock{GetCVEByIDResult: &schema.Cve{CVEID: cveId}},
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CveItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 1, result.TotalResults)
				assert.Equal(t, cveId, result.Items[0].Cve.CVEID)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCvePath)))
			},
		},
		{
			// Not found: search by cve ID
			ReqPath: getCvePath + "?cveId=" + cveId,
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CveItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 0, result.TotalResults)
				assert.Empty(t, result.Items)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusNotFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCvePath)))
			},
		},
		{
			// Error: search by cve ID
			ReqPath: getCvePath + "?cveId=" + cveId,
			DBMock:  testutils.DBMock{GetNVDError: errors.New("something happened")},
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusInternalServerError, code)
				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusError)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("500", getCvePath)))
			},
		},
		{
			// Found: search by keyword
			ReqPath: getCvePath + "?keywordSearch=" + cveKeyword,
			DBMock:  testutils.DBMock{GetCVEByKeywordResult: []schema.Cve{{CVEID: cveId}}},
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CveItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 1, result.TotalResults)
				assert.Equal(t, cveId, result.Items[0].Cve.CVEID)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCvePath)))
			},
		},
		{
			// Not found: search by keyword
			ReqPath: getCvePath + "?keywordSearch=" + cveKeyword,
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CveItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 0, result.TotalResults)
				assert.Empty(t, result.Items)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusNotFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCvePath)))
			},
		},
		{
			// Error: search by keyword
			ReqPath: getCvePath + "?keywordSearch=" + cveKeyword,
			DBMock:  testutils.DBMock{GetNVDError: errors.New("something happened")},
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusInternalServerError, code)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusError)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("500", getCvePath)))
			},
		},
	} {
		hdl, _ := NewNvdController("v1", &mock)

		r := gin.New()
		grpNVD := r.Group(APIGroupNVD)
		hdl.Register(grpNVD)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, mock.ReqPath, nil)
		r.ServeHTTP(w, req)

		mock.Assertion(w.Code, w.Body.String())

		httpRequestsTotal.Reset()
		getRequestsTotal.Reset()
	}
}

func TestHandlerGetCPE(t *testing.T) {
	reg := prometheus.NewRegistry()
	MetricRegisterOn(reg)
	defer MetricUnRegister(reg)

	cpeName := "cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*"
	cpeMatch := "cpe:2.3:a:dotproject"
	cpeKeyword := "dotproject"

	getCpePath := APIGroupNVD + "/v1" + APIPathGetCPE
	for _, mock := range []testutils.Mock{
		{
			ReqPath: getCpePath + "?",
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusBadRequest, code)
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("400", getCpePath)))
			},
		},
		{
			ReqPath: getCpePath + "?cpeName=" + cpeName + "&cpeMatchString=" + cpeMatch,
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusBadRequest, code)
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("400", getCpePath)))
			},
		},
		{
			// Found: search by cpe match string
			ReqPath: getCpePath + "?cpeMatchString=" + cpeMatch,
			DBMock:  testutils.DBMock{GetCPEByMatchResult: []schema.Cpe{{Name: cpeName}}},
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CpeItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 1, result.TotalResults)
				assert.Equal(t, cpeName, result.Items[0].Cpe.Name)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCpePath)))
			},
		},
		{
			// Not found: search by cpe match string
			ReqPath: getCpePath + "?cpeMatchString=" + cpeMatch,
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CpeItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 0, result.TotalResults)
				assert.Empty(t, result.Items)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusNotFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCpePath)))
			},
		},
		{
			// Error: search by cpe match string
			ReqPath: getCpePath + "?cpeMatchString=" + cpeMatch,
			DBMock:  testutils.DBMock{GetNVDError: errors.New("something happened")},
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusInternalServerError, code)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusError)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("500", getCpePath)))
			},
		},
		{
			// Found: search by cpe name
			ReqPath: getCpePath + "?cpeName=" + cpeName,
			DBMock:  testutils.DBMock{GetCPEByNameResult: &schema.Cpe{Name: cpeName}},
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CpeItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 1, result.TotalResults)
				assert.Equal(t, cpeName, result.Items[0].Cpe.Name)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCpePath)))
			},
		},
		{
			// Not found: search by cpe name
			ReqPath: getCpePath + "?cpeName=" + cpeName,
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CpeItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 0, result.TotalResults)
				assert.Empty(t, result.Items)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusNotFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCpePath)))
			},
		},
		{
			// Error: search by cpe name
			ReqPath: getCpePath + "?cpeName=" + cpeName,
			DBMock:  testutils.DBMock{GetNVDError: errors.New("something happened")},
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusInternalServerError, code)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusError)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("500", getCpePath)))
			},
		},
		{
			// Found: search by keyword
			ReqPath: getCpePath + "?keywordSearch=" + cpeKeyword,
			DBMock:  testutils.DBMock{GetCPEByKeywordResult: []schema.Cpe{{Name: cpeName}}},
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CpeItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 1, result.TotalResults)
				assert.Equal(t, cpeName, result.Items[0].Cpe.Name)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCpePath)))
			},
		},
		{
			// Not found: search by keyword
			ReqPath: getCpePath + "?keywordSearch=" + cpeKeyword,
			Assertion: func(code int, body string) {
				assert.Equal(t, http.StatusOK, code)
				var result schema.APIResp[schema.CpeItem]
				require.NoError(t, json.Unmarshal([]byte(body), &result))
				assert.Equal(t, 0, result.TotalResults)
				assert.Empty(t, result.Items)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusNotFound)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("200", getCpePath)))
			},
		},
		{
			// Error: search by keyword
			ReqPath: getCpePath + "?keywordSearch=" + cpeKeyword,
			DBMock:  testutils.DBMock{GetNVDError: errors.New("something happened")},
			Assertion: func(code int, _ string) {
				assert.Equal(t, http.StatusInternalServerError, code)

				assert.Equal(t, float64(1), testutil.ToFloat64(
					getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusError)))
				assert.Equal(t, float64(1), testutil.ToFloat64(
					httpRequestsTotal.WithLabelValues("500", getCpePath)))
			},
		},
	} {
		hdl, _ := NewNvdController("v1", &mock)

		r := gin.New()
		grpNVD := r.Group(APIGroupNVD)
		hdl.Register(grpNVD)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, mock.ReqPath, nil)
		r.ServeHTTP(w, req)

		mock.Assertion(w.Code, w.Body.String())

		httpRequestsTotal.Reset()
		getRequestsTotal.Reset()
	}
}

func TestGetExactlyOneQuery(t *testing.T) {
	k, v, err := getExactlyOneQuery(url.Values{QsCveId: []string{"CVE-2022-0001"}}, QsCveId, QsCpeName)
	require.NoError(t, err)
	assert.Equal(t, QsCveId, k)
	assert.Equal(t, "CVE-2022-0001", v)

	_, _, err = getExactlyOneQuery(url.Values{"abc": []string{"abc"}}, QsCveId, QsCpeName)
	assert.Error(t, err)

	_, _, err = getExactlyOneQuery(
		url.Values{"cveId": []string{"CVE-2022-0001"}, "cpeName": []string{"abc"}}, QsCveId, QsCpeName)
	assert.Error(t, err)
}
