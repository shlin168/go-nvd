package testutils

import (
	"context"

	"github.com/shlin168/go-nvd/db"
	"github.com/shlin168/go-nvd/nvd/schema"
)

// Mock mocks both DB and queue client for testing
type Mock struct {
	DBMock
	ReqPath   string
	ReqBody   string
	Assertion func(code int, body string)
}

// DBMock implememt db.DB interface to mock db client
type DBMock struct {
	GetCVEByIDResult      *schema.Cve
	GetCVEByCPEResult     []schema.Cve
	GetCVEByKeywordResult []schema.Cve
	GetCPEByNameResult    *schema.Cpe
	GetCPEByMatchResult   []schema.Cpe
	GetCPEByKeywordResult []schema.Cpe
	GetNVDError           error
}

func (mo *DBMock) ID() string {
	return "mock"
}

func (mo *DBMock) Init(ctx context.Context) error {
	return nil
}

func (mo *DBMock) Connect(ctx context.Context, uri string) error {
	return nil
}

func (mo *DBMock) IsConnected(ctx context.Context) error {
	return nil
}

func (mo *DBMock) Disconnect(ctx context.Context) error {
	return nil
}

func (mo *DBMock) UpsertCVE(ctx context.Context, cve schema.Cve) (bool, error) {
	return true, nil
}

func (mo *DBMock) UpsertCVEs(ctx context.Context, cve []schema.Cve) (int, error) {
	return 0, nil
}

func (mo *DBMock) UpsertCPE(ctx context.Context, cve schema.Cpe) (bool, error) {
	return true, nil
}

func (mo *DBMock) UpsertCPEs(ctx context.Context, cpe []schema.Cpe) (int, error) {
	return 0, nil
}

func (mo *DBMock) GetCVEByID(ctx context.Context, cveId string) (*schema.Cve, error) {
	if mo.GetNVDError != nil {
		return nil, mo.GetNVDError
	}
	if mo.GetCVEByIDResult != nil {
		return mo.GetCVEByIDResult, nil
	}
	return nil, db.ErrNotFound
}

func (mo *DBMock) GetCVEByCPE(ctx context.Context, cpeName string, opts ...db.QueryOptions) (*db.Result[schema.Cve], error) {
	if mo.GetNVDError != nil {
		return nil, mo.GetNVDError
	}
	if len(mo.GetCVEByCPEResult) > 0 {
		return &db.Result[schema.Cve]{
			Total:   len(mo.GetCVEByCPEResult),
			Size:    len(mo.GetCVEByCPEResult),
			Entries: mo.GetCVEByCPEResult,
		}, nil
	}
	return &db.Result[schema.Cve]{}, db.ErrNotFound
}

func (mo *DBMock) GetCVEByKeyword(ctx context.Context, keywords db.Keyword, opts ...db.QueryOptions) (*db.Result[schema.Cve], error) {
	if mo.GetNVDError != nil {
		return nil, mo.GetNVDError
	}
	if len(mo.GetCVEByKeywordResult) > 0 {
		return &db.Result[schema.Cve]{
			Total:   len(mo.GetCVEByKeywordResult),
			Size:    len(mo.GetCVEByKeywordResult),
			Entries: mo.GetCVEByKeywordResult,
		}, nil
	}
	return &db.Result[schema.Cve]{}, db.ErrNotFound
}

func (mo *DBMock) GetCPEByName(ctx context.Context, cpeName string) (*schema.Cpe, error) {
	if mo.GetNVDError != nil {
		return nil, mo.GetNVDError
	}
	if mo.GetCPEByNameResult != nil {
		return mo.GetCPEByNameResult, nil
	}
	return nil, db.ErrNotFound
}

func (mo *DBMock) GetCPEByMatchString(ctx context.Context, cpeNameMatchString string, opts ...db.QueryOptions) (*db.Result[schema.Cpe], error) {
	if mo.GetNVDError != nil {
		return nil, mo.GetNVDError
	}
	if len(mo.GetCPEByMatchResult) > 0 {
		return &db.Result[schema.Cpe]{
			Total:   len(mo.GetCPEByMatchResult),
			Size:    len(mo.GetCPEByMatchResult),
			Entries: mo.GetCPEByMatchResult,
		}, nil
	}
	return &db.Result[schema.Cpe]{}, db.ErrNotFound
}

func (mo *DBMock) GetCPEByKeyword(ctx context.Context, keywords db.Keyword, opts ...db.QueryOptions) (*db.Result[schema.Cpe], error) {
	if mo.GetNVDError != nil {
		return nil, mo.GetNVDError
	}
	if len(mo.GetCPEByKeywordResult) > 0 {
		return &db.Result[schema.Cpe]{
			Total:   len(mo.GetCPEByKeywordResult),
			Size:    len(mo.GetCPEByKeywordResult),
			Entries: mo.GetCPEByKeywordResult,
		}, nil
	}
	return &db.Result[schema.Cpe]{}, db.ErrNotFound
}
