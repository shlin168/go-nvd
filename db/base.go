package db

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.uber.org/zap"

	"github.com/shlin168/go-nvd/nvd/schema"
	"github.com/shlin168/go-nvd/utils"
)

const (
	// DefaultTimeout is the default timeout for each db operation
	DefaultTimeout = 10 * time.Second

	// GetSizeUnlimited is the constant to indicate that there's no size limit for db return record size.
	GetSizeUnlimited = -1
)

var (
	// ErrNotFound is general not found error for all structs that implement Nvd[Cve|Cpe]DB interface
	// It is expected to return this error if the input is not found in the table
	ErrNotFound = errors.New("not found")

	// ErrPageEnd is the error to indicate that the start index is larger than the total number of entries
	ErrPageEnd = errors.New("page end")
)

// DB is the interface to record information and handle general operations
// such as connect and disconnect to database.
type DB interface {
	ID() string
	Init(ctx context.Context) error
	Connect(ctx context.Context, uri string) error
	Disconnect(ctx context.Context) error
	IsConnected(ctx context.Context) error
}

// NvdCveDB is the interface to define the operations related to NVD API for CVE
type NvdCveDB interface {
	GetCVEByID(ctx context.Context, cveId string) (*schema.Cve, error)
	GetCVEByCPE(ctx context.Context, cpeName string, opts ...QueryOptions) (*Result[schema.Cve], error)
	GetCVEByKeyword(ctx context.Context, keywords Keyword, opts ...QueryOptions) (*Result[schema.Cve], error)
}

// NvdCpeDB is the interface to define the operations related to NVD API for CPE
type NvdCpeDB interface {
	GetCPEByName(ctx context.Context, cpeName string) (*schema.Cpe, error)
	GetCPEByMatchString(ctx context.Context, cpeNameMatchString string, opts ...QueryOptions) (*Result[schema.Cpe], error)
	GetCPEByKeyword(ctx context.Context, keyword Keyword, opts ...QueryOptions) (*Result[schema.Cpe], error)
}

// Keyword defines how a keyword matches with the description of CVE or CPE
type Keyword struct {
	// Val is the content to match
	Val string

	// ExactMatch decides whether matching all the words includes space or not.
	// E.g.,
	// * Val="Hello World" and `ExactMatch=true`: matches with "Hello World"
	// * Val="Hello World" and `ExactMatch=false`: matches with "Hello" AND "World"
	ExactMatch bool
}

// Config is the general(default) config to initialize the collection or control the db logic.
type Config struct {
	Timeout time.Duration
	Batch   int
	Logger  *zap.Logger
}

// QueryConfig is the config for each DB query
// Use options to stay flexible for future extension
type QueryConfig struct {
	Start int
	Size  int
}

type QueryOptions func(*QueryConfig) error

func StartWith(start int) QueryOptions {
	return func(cfg *QueryConfig) error {
		if start < 0 {
			return fmt.Errorf("invalid start index, should be 0 or positive number")
		}
		cfg.Start = start
		return nil
	}
}

func Size(size int) QueryOptions {
	return func(cfg *QueryConfig) error {
		if size <= 0 && size != GetSizeUnlimited {
			return fmt.Errorf("invalid size, should be either -1(unlimited) or positive number")
		}
		cfg.Size = size
		return nil
	}
}

// NewConfig initializes config with default value
func NewConfig() Config {
	return Config{
		Timeout: DefaultTimeout,
		Batch:   1,
		Logger:  utils.DefaultLogger,
	}
}

// Validate validates config
func (cfg Config) Validate() error {
	if cfg.Timeout <= 0 {
		return fmt.Errorf("invalid timeout for Timeout")
	}
	if cfg.Batch < 1 {
		return fmt.Errorf("invalid batch size, should be positive number")
	}
	return nil
}

// GetQueryConfig gets the query config with given options, use default value in Config if not specified
func GetQueryConfig(opts ...QueryOptions) (QueryConfig, error) {
	qConfig := QueryConfig{Size: GetSizeUnlimited}
	for _, opt := range opts {
		if err := opt(&qConfig); err != nil {
			return QueryConfig{Size: GetSizeUnlimited}, err
		}
	}
	return qConfig, nil
}

// NVDUnit is the interface to define the possible type of response, which is either CVE or CPE
type NVDUnit interface {
	schema.Cve | schema.Cpe
}

// Result is the result of a query, including the total number of entries, the start index, the size of the result.
// Since the result is paginated, the entries are the entries from start to start+size.
// While total is the total number before pagination.
type Result[T NVDUnit] struct {
	Total, Start, Size int
	Entries            []T // result entries from start to start+size
}

// Filter filters the entries with the given function, which is used for complex conditions which is implemented
// by the caller with code after getting the result from database.
// It is expected to be invoke before pagination.
func (r Result[T]) Filter(fn func(item T) bool) Result[T] {
	var filtered []T
	for _, item := range r.Entries {
		if fn(item) {
			filtered = append(filtered, item)
		}
	}
	return Result[T]{
		Total:   len(filtered),
		Start:   0,
		Size:    len(filtered),
		Entries: filtered,
	}
}

// Sort sorts the entries with the given function
func (r *Result[T]) Sort(sortFn func(i, j int) bool) {
	sort.Slice(r.Entries, sortFn)
}

// GetPaginated gets the paginated result from the result based on given start and size.
// start and size should be checked before calling this function.
// * start should be 0 or positive number
// * size should be positive number
func (r Result[T]) GetPaginated(start, size int) Result[T] {
	ret := Result[T]{
		Total: r.Total,
		Start: start,
		Size:  size,
	}

	if size == GetSizeUnlimited || start+size > len(r.Entries) {
		ret.Entries = r.Entries[start:]
		ret.Size = len(ret.Entries)
		return ret
	}

	ret.Entries = r.Entries[start : start+size]
	return ret
}

func (r Result[T]) IsPageEnd() bool {
	return (r.Start >= len(r.Entries)) || (len(r.Entries) == 0 && r.Total > 0)
}

// IsNotFound checks whether the error belongs to data not found in database
func IsNotFound(err error) bool {
	return err == ErrNotFound || err == mongo.ErrNoDocuments
}

// IsPageEnd checks whether the error belongs to page end
func IsPageEnd(err error) bool {
	return err == ErrPageEnd
}

// IsUnexpectedError checkes whether the error belongs to unexpected error in database
func IsUnexpectedError(err error) bool {
	return err != nil && !IsNotFound(err) && !IsPageEnd(err)
}

func execBatch(batch, endIdx int, procFn func(start, end int) (batchUpCnt int, err error), logger *zap.Logger) (upsertedCnt int, err error) {
	startIdx := 0
	for startIdx+batch-1 <= endIdx {
		batchEndIdx := startIdx + batch - 1
		bUpCnt, err := procFn(startIdx, batchEndIdx)
		upsertedCnt += bUpCnt
		if err != nil {
			logger.Warn("upsert record", zap.Int("start", startIdx), zap.Int("end", batchEndIdx), zap.Error(err))
			return upsertedCnt, err
		}
		logger.Debug("upsert record", zap.Int("start", startIdx), zap.Int("end", batchEndIdx))
		startIdx = batchEndIdx + 1
	}

	// last batch
	if startIdx <= endIdx {
		bUpCnt, err := procFn(startIdx, endIdx)
		upsertedCnt += bUpCnt
		if err != nil {
			logger.Warn("upsert record", zap.Int("start", startIdx), zap.Int("end", endIdx), zap.Error(err))
			return upsertedCnt, err
		}
		logger.Debug("upsert record", zap.Int("start", startIdx), zap.Int("end", endIdx))
	}

	return upsertedCnt, nil
}
