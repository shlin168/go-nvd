package nvd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"

	"github.com/shlin168/go-nvd/nvd/schema"
	"github.com/shlin168/go-nvd/utils"
)

const (
	NVDBaseCVEURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	NVDBaseCPEURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

	DefaultWaitInterval = time.Second

	DefaultQueryTimeFormat = "2006-01-02"
)

type Querier[T schema.APIRespItem] struct {
	url         string
	apikey      string        // optional, it's not mandatory to query NVD API
	waitEachReq time.Duration // sleep before each query
	logger      *zap.Logger
}

func (qr Querier[T]) composeReq(sdate, edate string, startIdx int) (*retryablehttp.Request, error) {
	req, err := retryablehttp.NewRequest(http.MethodGet, qr.url, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("lastModStartDate", sdate)
	q.Add("lastModEndDate", edate)
	if startIdx > 0 {
		q.Add("startIndex", strconv.Itoa(startIdx))
	}

	req.URL.RawQuery = q.Encode()
	if len(qr.apikey) > 0 {
		req.Header.Add("apiKey", qr.apikey)
	}

	return req, nil
}

func (qr Querier[T]) getDataInLastModRange(cli *retryablehttp.Client, req *retryablehttp.Request) (*schema.APIResp[T], error) {
	rsp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected rsp code: %d", rsp.StatusCode)
	}

	var parsedResp schema.APIResp[T]
	if err := json.NewDecoder(rsp.Body).Decode(&parsedResp); err != nil {
		return nil, err
	}

	return &parsedResp, nil
}

func (qr Querier[T]) GetDataInLastModRange(cli *retryablehttp.Client, sdate, edate string) (*schema.APIResp[T], error) {
	if _, err := time.Parse(DefaultQueryTimeFormat, sdate); err != nil {
		return nil, err
	}
	if _, err := time.Parse(DefaultQueryTimeFormat, edate); err != nil {
		return nil, err
	}
	sdate += "T00:00:00.000"
	edate += "T00:00:00.000"

	aggrResult := &schema.APIResp[T]{}
	aggrResult.Init()

	var startIdx int
	var times int
	var merr error

	for startIdx == 0 || startIdx < aggrResult.TotalResults {
		times++

		req, err := qr.composeReq(sdate, edate, startIdx)
		if err != nil {
			merr = errors.Join(merr, err)
			break
		}

		qr.logger.Info("query: " + req.URL.String())
		rsp, err := qr.getDataInLastModRange(cli, req)
		if err != nil || len(rsp.Items) == 0 {
			if err != nil {
				merr = errors.Join(merr, err)
			}
			break
		}
		if aggrResult.TotalResults == 0 {
			aggrResult = rsp
			startIdx += rsp.ResultsPerPage
			continue
		}
		aggrResult.Items = append(aggrResult.Items, rsp.Items...)
		startIdx += rsp.ResultsPerPage

		time.Sleep(qr.waitEachReq)
	}
	aggrResult.StartIndex = 0

	qr.logger.Info(fmt.Sprintf("query nvd %d times", times),
		zap.String("start", sdate), zap.String("end", edate))

	return aggrResult, merr
}

// Client is the client to query NVD API
type Client struct {
	cli        *retryablehttp.Client
	cveQuerier Querier[schema.CveItem]
	cpeQuerier Querier[schema.CpeItem]
}

type Option func(*Client) error

func Timeout(timeout time.Duration) Option {
	return func(c *Client) error {
		if timeout <= 0 {
			return fmt.Errorf("invalid timeout: %v, should > 0", timeout)
		}
		c.cli.HTTPClient.Timeout = timeout
		return nil
	}
}

func Retries(retries int) Option {
	return func(c *Client) error {
		if retries < 0 {
			return fmt.Errorf("invalid retries: %d, should be a positive number", retries)
		}
		c.cli.RetryMax = retries
		return nil
	}
}

func APIKey(apikey string) Option {
	return func(c *Client) error {
		c.cveQuerier.apikey = apikey
		c.cpeQuerier.apikey = apikey
		return nil
	}
}

func Wait(wait time.Duration) Option {
	return func(c *Client) error {
		if wait <= 0 {
			return fmt.Errorf("invalid timeout: %v, should > 0", wait)
		}
		c.cveQuerier.waitEachReq = wait
		c.cpeQuerier.waitEachReq = wait
		return nil
	}
}

func BaseCVEURL(url string) Option {
	return func(c *Client) error {
		c.cveQuerier.url = url
		return nil
	}
}

func BaseCPEURL(url string) Option {
	return func(c *Client) error {
		c.cpeQuerier.url = url
		return nil
	}
}

func Logger(logger *zap.Logger) Option {
	return func(c *Client) error {
		c.cveQuerier.logger = logger
		c.cpeQuerier.logger = logger
		return nil
	}
}

func NewClient(opts ...Option) (*Client, error) {
	cli := &Client{
		cli: retryablehttp.NewClient(),
		cveQuerier: Querier[schema.CveItem]{
			url:         NVDBaseCVEURL,
			waitEachReq: DefaultWaitInterval,
			logger:      utils.DefaultLogger,
		},
		cpeQuerier: Querier[schema.CpeItem]{
			url:         NVDBaseCPEURL,
			waitEachReq: DefaultWaitInterval,
			logger:      utils.DefaultLogger,
		},
	}

	for _, opt := range opts {
		if err := opt(cli); err != nil {
			return nil, err
		}
	}

	cli.cli.Logger = nil // disable retryable http client's logger
	return cli, nil
}

func (c Client) GetCVEsInRange(sdate, edate string) (*schema.APIResp[schema.CveItem], error) {
	rsp, err := c.cveQuerier.GetDataInLastModRange(c.cli, sdate, edate)
	if err != nil {
		return nil, err
	}
	rsp.Sort(func(i, j int) bool {
		return rsp.Items[i].Cve.LastModified < rsp.Items[j].Cve.LastModified
	})
	return rsp, nil
}

func (c Client) GetCPEsInRange(sdate, edate string) (*schema.APIResp[schema.CpeItem], error) {
	rsp, err := c.cpeQuerier.GetDataInLastModRange(c.cli, sdate, edate)
	if err != nil {
		return nil, err
	}
	rsp.Sort(func(i, j int) bool {
		if rsp.Items[i].Cpe.LastModified == nil {
			return true
		}
		if rsp.Items[j].Cpe.LastModified == nil {
			return false
		}
		return *rsp.Items[i].Cpe.LastModified < *rsp.Items[j].Cpe.LastModified
	})
	return rsp, nil
}
