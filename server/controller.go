package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/shlin168/go-nvd/db"
	"github.com/shlin168/go-nvd/nvd/schema"
)

const (
	// CVEResultsPerPage is the default resultsPerPage for NVD CVE API
	CVEResultsPerPage = 2000

	// CPEResultsPerPage is the default resultsPerPage for NVD CPE API
	// The document declares with 5000 while it is actually 10000
	CPEResultsPerPage = 10000
)

// Controller is the interface to implement a router group which is registered to *gin.Engine with Register function
type Controller interface {
	Register(*gin.RouterGroup, ...gin.HandlerFunc)
}

// NvdDB defines the interface that NvdController needs to handle requests
type NvdDB interface {
	db.DB
	db.NvdCveDB
	db.NvdCpeDB
}

// NvdController is the controller to handle requests from asking NVD information
type NvdController struct {
	subGrpName string // the sub api path after '/nvd'. E.g., subGrpName='v1' means that api is registered with '/nvd/v1/...'
	dbCli      NvdDB
}

// NewNvdController initializes controller, and the return instance provides what the handler needs (E.g., db and queue client)
func NewNvdController(subGrpName string, dbCli NvdDB) (*NvdController, error) {
	if dbCli == nil {
		return nil, errors.New("db client can not be nil")
	}
	if len(subGrpName) == 0 {
		return nil, errors.New("sub group name can not be empty")
	}
	return &NvdController{subGrpName: subGrpName, dbCli: dbCli}, nil
}

// Register implements Controller interface to register group of Routes to gin Engine
func (h NvdController) Register(grp *gin.RouterGroup, hdlFuncs ...gin.HandlerFunc) {
	v1 := grp.Group("/"+h.subGrpName, hdlFuncs...)
	v1.GET(APIPathReady, h.ready)
	v1.GET(APIPathGetCVE, MetricMiddleware(), h.getCVE)
	v1.GET(APIPathGetCPE, MetricMiddleware(), h.getCPE)
}

func (h NvdController) ready(c *gin.Context) {
	pingCtx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	err := h.dbCli.IsConnected(pingCtx)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, err.Error())
		return
	}
	defer h.dbCli.Disconnect(c.Request.Context())

	c.JSON(http.StatusOK, "I'm ready")
}

func (h NvdController) getCVE(c *gin.Context) {
	key, val, err := getExactlyOneQuery(c.Request.URL.Query(), CVEQSKeys...)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
		return
	}

	switch key {
	case QsCveId:
		if !schema.IsValidCVE(val) {
			c.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
			return
		}
		cveResult, err := h.dbCli.GetCVEByID(c.Request.Context(), val)
		if db.IsUnexpectedError(err) {
			c.JSON(http.StatusInternalServerError, err.Error())
			getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusError).Inc()
			return
		}
		resp := &schema.APIResp[schema.CveItem]{}
		resp.Init()
		if db.IsNotFound(err) {
			c.JSON(http.StatusOK, resp)
			getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusNotFound).Inc()
			return
		}
		resp.ResultsPerPage = 1
		resp.TotalResults = 1
		resp.Items = []schema.CveItem{{Cve: *cveResult}}

		getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusFound).Inc()
		c.JSON(http.StatusOK, resp)
		return
	case QsCpeName, QsKeyword:
		startIdx, resultsPerPage, err := setNvdPage(c, CVEResultsPerPage)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
			return
		}

		var result *db.Result[schema.Cve]
		switch key {
		case QsCpeName:
			// cpe name is checked within GetCVEByCPE function, while the function only expect string with lowercase
			result, err = h.dbCli.GetCVEByCPE(c.Request.Context(), strings.ToLower(val),
				db.StartWith(startIdx), db.Size(resultsPerPage))
		case QsKeyword:
			_, exist := c.GetQuery(QsKeywordExact)
			result, err = h.dbCli.GetCVEByKeyword(c.Request.Context(), db.Keyword{Val: val, ExactMatch: exist},
				db.StartWith(startIdx), db.Size(resultsPerPage))
		}

		if db.IsUnexpectedError(err) {
			getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusError).Inc()
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		resp := &schema.APIResp[schema.CveItem]{}
		resp.Init()

		// result should not be nil from here, just play it safe to avoid error
		if result != nil {
			resp.ResultsPerPage = result.Size
			resp.StartIndex = result.Start
			resp.TotalResults = result.Total
		}

		if db.IsNotFound(err) {
			getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusNotFound).Inc()
			c.JSON(http.StatusOK, resp)
			return
		}

		for i := range result.Entries {
			resp.Items = append(resp.Items, schema.CveItem{Cve: result.Entries[i]})
		}

		getRequestsTotal.WithLabelValues(APIPathGetCVE, StatusFound).Inc()
		c.JSON(http.StatusOK, resp)
		return
	}
	c.AbortWithStatus(http.StatusInternalServerError)
}

func (h NvdController) getCPE(c *gin.Context) {
	key, val, err := getExactlyOneQuery(c.Request.URL.Query(), CPEQSKeys...)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
		return
	}

	switch key {
	case QsCpeName:
		if schema.NewCPEParsed(val) == nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, fmt.Errorf("invalid cpe name: %s", val))
			return
		}
		resultCPE, err := h.dbCli.GetCPEByName(c.Request.Context(), val)
		if db.IsUnexpectedError(err) {
			getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusError).Inc()
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		resp := &schema.APIResp[schema.CpeItem]{}
		resp.Init()
		if db.IsNotFound(err) {
			getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusNotFound).Inc()
			c.JSON(http.StatusOK, resp)
			return
		}
		resp.TotalResults = 1
		resp.ResultsPerPage = 1
		resp.Items = []schema.CpeItem{{
			Cpe: *resultCPE,
		}}

		getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusFound).Inc()
		c.JSON(http.StatusOK, resp)
		return
	case QsCpeMatchStr, QsKeyword:
		startIdx, resultsPerPage, err := setNvdPage(c, CPEResultsPerPage)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
			return
		}

		var result *db.Result[schema.Cpe]
		switch key {
		case QsCpeMatchStr:
			if schema.NewCPEParsedMap(val) == nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, fmt.Errorf("invalid cpe match string: %s", val))
				return
			}
			result, err = h.dbCli.GetCPEByMatchString(c.Request.Context(), val,
				db.StartWith(startIdx), db.Size(resultsPerPage))
		case QsKeyword:
			_, exist := c.GetQuery(QsKeywordExact)
			result, err = h.dbCli.GetCPEByKeyword(c.Request.Context(), db.Keyword{Val: val, ExactMatch: exist},
				db.StartWith(startIdx), db.Size(resultsPerPage))
		}

		if db.IsUnexpectedError(err) {
			getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusError).Inc()
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}

		resp := &schema.APIResp[schema.CpeItem]{}
		resp.Init()

		// result should not be nil from here, just play it safe to avoid error
		if result != nil {
			resp.ResultsPerPage = result.Size
			resp.StartIndex = result.Start
			resp.TotalResults = result.Total
		}

		if db.IsNotFound(err) {
			getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusNotFound).Inc()
			c.JSON(http.StatusOK, resp)
			return
		}

		for i := range result.Entries {
			resp.Items = append(resp.Items, schema.CpeItem{Cpe: result.Entries[i]})
		}

		getRequestsTotal.WithLabelValues(APIPathGetCPE, StatusFound).Inc()
		c.JSON(http.StatusOK, resp)
		return
	}
	c.AbortWithStatus(http.StatusInternalServerError)
}

func setNvdPage(c *gin.Context, maxResultsPerPage int) (startIdx, resultsPerPage int, err error) {
	startIdxStr := c.Query(QsStartIndex)
	resultPerPageStr := c.Query(QsResultsPerPage)
	resultsPerPage = maxResultsPerPage
	if len(startIdxStr) > 0 {
		s, err := strconv.Atoi(startIdxStr)
		if err != nil || s < 0 {
			return startIdx, resultsPerPage, errors.New("startIdx should be 0 or positive integer")
		}
		startIdx = s
	}
	if len(resultPerPageStr) > 0 {
		rps, err := strconv.Atoi(resultPerPageStr)
		if err != nil || rps <= 0 {
			return startIdx, resultsPerPage, errors.New("resultsPerPage should be positive integer")
		}
		if rps > maxResultsPerPage {
			return startIdx, resultsPerPage, fmt.Errorf("resultsPerPage should be less than %d", maxResultsPerPage)
		}
		resultsPerPage = rps
	}
	return startIdx, resultsPerPage, nil
}

// getExactlyOneQuery checks if only one of the key is given in query strings, return error if multiple or zero keys is given.
// The given key and value is returned if there's no error.
// Usage
//
//	// Valid query string
//	val := url.Values{QsCveId: []string{"CVE-2022-0001"}}
//	k, v, err := getExactlyOneQuery(val, "cveId", "cpeName")
//	require.NoError(t, err)
//	assert.Equal(t, "cveId", k)
//	assert.Equal(t, "CVE-2022-0001", v)
//
//	// Invalid query string (error since both 'cveId' and 'cpeName' are not provided)
//	val := url.Values{"abc": []string{"abc"}}
//	k, v, err := getExactlyOneQuery(val, "cveId", "cpeName")
//	assert.Error(t, err)
//
//	// Invalid query string (error since it's not valid to provide both keys)
//	val := url.Values{"cveId": []string{"CVE-2022-0001"}}, "cpeName": []string{"..."}}}
//	k, v, err := getExactlyOneQuery(val, "cveId", "cpeName")
//	assert.Error(t, err)
func getExactlyOneQuery(q url.Values, qsKeys ...string) (k, v string, err error) {
	var retKey, retVal string
	var hasValCnt int

	for _, key := range qsKeys {
		if val := q.Get(key); len(val) > 0 {
			hasValCnt++
			if hasValCnt > 1 {
				return "", "", fmt.Errorf("expected to only provide one from the list: %v", qsKeys)
			}
			retKey, retVal = key, val
		}
	}

	if len(retVal) == 0 {
		return "", "", fmt.Errorf("expected to provide one query parameter from the list: %v", qsKeys)
	}

	return retKey, retVal, nil
}
