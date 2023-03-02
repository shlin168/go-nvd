package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/shlin168/go-nvd/nvd/schema"
	"github.com/shlin168/go-nvd/utils"
)

const (
	MongoDBID = "mongo"

	// DBNvd is the database name of nvd service
	DBNvd = "nvd"

	// CltCve and CltCpe are collection name in 'DBNvd'
	CltCve = "cve"
	CltCpe = "cpe"

	MongoTLSTemplate = "mongodb://%s:%s@%s/nvd?tls=true&replicaSet=rs0&retryWrites=false"
)

var (
	// DefaultGetMongoURI is the url template to connect to local testing mongo db,
	// query string of URI might be different when connecting to db with different authenication method
	DefaultGetMongoURI = func(user, pwd, endpoint string) string {
		return fmt.Sprintf("mongodb://%s:%s@%s/nvd?authSource=admin", user, pwd, endpoint)
	}
)

// Mongo is the db client to handle mongo db operations
type Mongo struct {
	getURI     func(user, pwd, endpoint string) string
	cfg        Config
	client     *mongo.Client
	clientOpts []*options.ClientOptions
}

// MongoOptions is the options of Mongo client
type MongoOptions func(*Mongo) error

// MongoClientOptions appends additional mongo options to client
func MongoClientOptions(opts ...*options.ClientOptions) MongoOptions {
	return func(mdb *Mongo) error {
		mdb.clientOpts = opts
		return nil
	}
}

// MongoConfig is expected to use only in testing to mock the client
func MongoConfig(cfg Config) MongoOptions {
	return func(mdb *Mongo) error {
		mdb.cfg = cfg
		return mdb.cfg.Validate()
	}
}

// MongoTestClient is expected to use only in testing to mock the client
func MongoTestClient(client *mongo.Client) MongoOptions {
	return func(mdb *Mongo) error {
		mdb.client = client
		return nil
	}
}

// MongoGetURI overwrites default function to get uri to connect to database
func MongoGetURI(fn func(user, pwd, endpoint string) string) MongoOptions {
	return func(mdb *Mongo) error {
		mdb.getURI = fn
		return nil
	}
}

// NewMongo initializes db client to interact with mongo db
func NewMongo(user, pwd, endpoint string, opts ...MongoOptions) (*Mongo, error) {
	db := &Mongo{cfg: NewConfig(), getURI: DefaultGetMongoURI}
	for _, opt := range opts {
		if err := opt(db); err != nil {
			return nil, err
		}
	}

	// if db.client is given, then not trying to connect for testing
	if db.client == nil {
		ctx, cancel := context.WithTimeout(context.Background(), db.cfg.Timeout)
		defer cancel()

		if err := db.Connect(ctx, db.getURI(user, pwd, endpoint)); err != nil {
			return nil, err
		}
	}

	if db.cfg.Logger == nil {
		db.cfg.Logger = utils.DefaultLogger
	}

	return db, nil
}

func (Mongo) ID() string {
	return MongoDBID
}

// Connect connects to mongo db with provided uri and options
func (mdb *Mongo) Connect(ctx context.Context, uri string) (err error) {
	opts := append([]*options.ClientOptions{options.Client().ApplyURI(uri)}, mdb.clientOpts...)
	cli, err := mongo.Connect(ctx, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	mdb.client = cli

	// Force a connection to verify our connection string
	return mdb.IsConnected(ctx)
}

// IsConnected checks if mongo db is reachable, which is expected to be used for health check endpoint
func (mdb Mongo) IsConnected(ctx context.Context) error {
	if mdb.client == nil {
		return errors.New("client is nil")
	}
	return mdb.client.Ping(ctx, nil)
}

// Init creates collections and TTL indexes and text indexes for NVD service.
// It should be only used when initializing environment.
//
// The same mongo command as below:
//
//	$ use nvd;
//	$ db.cve.createIndex({ "cveId": 1 }, { unique: true, name: "cveId" });
//	$ db.cve.createIndex({ "configurations.nodes.cpeMatch.criteria": 1 }, { name: "cpeName" });
//	$ db.cve.createIndex({ "configurations.nodes.cpeMatch.criteriaProductPrefix": 1 }, { name: "cpeNameProductPrefix" });
//	$ db.cve.createIndex({ "descriptions.value": "text" }, { name: "keyword" });
//	$ db.cpe.createIndex({ "cpeName": 1 }, { unique: true, name: "cpeName" });
//	$ db.cpe.createIndex({ "titles.title": "text", "refs.ref": "text" }, { name: "keyword" });
func (mdb Mongo) Init(ctx context.Context) error {
	iCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	var result bson.M
	command := bson.D{primitive.E{Key: "create", Value: CltCve}}
	if err := mdb.client.Database(DBNvd).RunCommand(iCtx, command).Decode(&result); err != nil {
		return fmt.Errorf("create collection %s err: %w", CltCve, err)
	}

	models := []mongo.IndexModel{{
		// CVE ID
		Keys:    bson.M{"cveId": 1},
		Options: options.Index().SetUnique(true).SetName("cveId"),
	}, {
		// CPE 2.3
		Keys:    bson.M{"configurations.nodes.cpeMatch.criteria": 1},
		Options: options.Index().SetName("cpeName"),
	}, {
		// CPE 2.3 Product Prefix
		Keys:    bson.M{"configurations.nodes.cpeMatch.criteriaProductPrefix": 1},
		Options: options.Index().SetName("cpeNameProductPrefix"),
	}, {
		// text index
		// db.cve.createIndex({ "descriptions.value": "text" }, { name: "keyword" });
		Keys:    bson.D{primitive.E{Key: "descriptions.value", Value: "text"}},
		Options: options.Index().SetName("keyword"),
	}}

	if _, err := mdb.client.Database(DBNvd).Collection(CltCve).Indexes().CreateMany(iCtx, models); err != nil {
		return fmt.Errorf("create indexs for %s error: %w", CltCve, err)
	}

	models = []mongo.IndexModel{{
		// CPE 2.3
		Keys:    bson.M{"cpeName": 1},
		Options: options.Index().SetUnique(true).SetName("cpeName"),
	}, {
		// text index
		// db.cpe.createIndex({ "titles.title": "text", "refs.ref": "text" }, { "name": "keyword" });
		Keys:    bson.D{primitive.E{Key: "titles.title", Value: "text"}, primitive.E{Key: "refs.ref", Value: "text"}},
		Options: options.Index().SetName("keyword"),
	}}

	if _, err := mdb.client.Database(DBNvd).Collection(CltCpe).Indexes().CreateMany(iCtx, models); err != nil {
		return fmt.Errorf("create indexs for %s error: %w", CltCve, err)
	}

	return nil
}

// Disconnect closes connection to database
func (mdb *Mongo) Disconnect(ctx context.Context) error {
	return mdb.client.Disconnect(ctx)
}

func (mdb Mongo) cve() *mongo.Collection {
	return mdb.client.Database(DBNvd).Collection(CltCve)
}

func (mdb Mongo) cpe() *mongo.Collection {
	return mdb.client.Database(DBNvd).Collection(CltCpe)
}

type mongoPGInfo struct {
	Count int32 `bson:"count"`
}

// mongoPG is the struct to store the result of paginated query, with total count included
type mongoPG[T NVDUnit] struct {
	Info             []mongoPGInfo `bson:"info"`
	PaginatedResults []T           `bson:"paginatedResults"`
}

func mongoPaginatedQuery[T NVDUnit](ctx context.Context, clt *mongo.Collection, target bson.D, qCfg QueryConfig) (*Result[T], error) {
	matchStage := bson.D{primitive.E{Key: "$match", Value: target}}
	grpPgResults := bson.A{bson.D{primitive.E{Key: "$skip", Value: qCfg.Start}}}
	if qCfg.Size > GetSizeUnlimited {
		grpPgResults = append(grpPgResults, bson.D{primitive.E{Key: "$limit", Value: qCfg.Size}})
	}
	grpTotalCount := bson.A{bson.D{primitive.E{Key: "$count", Value: "count"}}}
	groupStage := bson.D{primitive.E{Key: "$facet", Value: bson.D{
		primitive.E{Key: "paginatedResults", Value: grpPgResults},
		primitive.E{Key: "info", Value: grpTotalCount},
	}}}

	cursor, err := clt.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage})
	if err != nil {
		return nil, err
	}

	var results []mongoPG[T]
	if err := cursor.All(ctx, &results); err != nil {
		return nil, err
	}
	r := &Result[T]{Start: qCfg.Start}
	if len(results) == 0 || len(results[0].Info) == 0 {
		return r, ErrNotFound
	}

	totalCnt := int(results[0].Info[0].Count)
	if totalCnt == 0 {
		return r, ErrNotFound
	}

	pgResult := results[0].PaginatedResults
	r.Total = totalCnt
	r.Size = len(pgResult)
	r.Entries = pgResult
	if r.IsPageEnd() {
		return r, ErrPageEnd
	}

	return r, nil
}

// UpsertCVE inserts or replaces an CVE record in 'nvd.cve' collection.
// It replaces when the incoming CVE record contains latest 'lastModified'.
//
// It use string comparison since all the value in "lastModified" is converted to same time format,
// and the first return value shows whether the the cve has been upserted after this function
func (mdb Mongo) UpsertCVE(ctx context.Context, cve schema.Cve) (upserted bool, err error) {
	updateCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	// query: { "cveId": "CVE-2007-6442", "lastModified": { $lte: "2008-01-10T05:00:00.000" } }
	replaceTarget := bson.D{
		primitive.E{Key: "cveId", Value: cve.CVEID},
		primitive.E{Key: "lastModified", Value: bson.D{primitive.E{Key: "$lte", Value: cve.LastModified}}}}

	cve.AddCriteriaProductPrefixs()
	upsert, err := mdb.cve().ReplaceOne(updateCtx, replaceTarget, cve, options.Replace().SetUpsert(true))
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			mdb.cfg.Logger.Debug(fmt.Sprintf("Latest CVE ID %s in db, not replace", cve.CVEID))
			return false, nil
		}
		return false, err
	}

	// cve in collection has been either inserted or updated
	if upsert.ModifiedCount+upsert.UpsertedCount > 0 {
		return true, nil
	}

	return false, nil
}

// UpsertCVEs upserts CVEs to 'nvd.cve' collection in batch
func (mdb Mongo) UpsertCVEs(ctx context.Context, cves []schema.Cve) (upsertedCnt int, err error) {
	upsertBatch := func(start, end int) (batchUpCnt int, err error) {
		updateCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
		defer cancel()
		var models []mongo.WriteModel
		for i := start; i <= end; i++ {
			cve := cves[i]
			cve.AddCriteriaProductPrefixs()
			replaceTarget := bson.D{
				primitive.E{Key: "cveId", Value: cve.CVEID},
				primitive.E{Key: "lastModified", Value: bson.D{primitive.E{Key: "$lte", Value: cve.LastModified}}}}
			models = append(models, mongo.NewReplaceOneModel().SetFilter(replaceTarget).SetReplacement(cve).SetUpsert(true))
		}
		opts := options.BulkWrite().SetOrdered(true)
		upsert, err := mdb.cve().BulkWrite(updateCtx, models, opts)
		if err != nil {
			return batchUpCnt, err
		}
		return int(upsert.ModifiedCount + upsert.UpsertedCount), nil
	}

	return execBatch(mdb.cfg.Batch, len(cves)-1, upsertBatch, mdb.cfg.Logger)
}

// UpsertCPE inserts or replaces an CPE record in 'nvd.cpe' collection.
// It Replaces when the incoming CPE record contains latest 'lastModified'.
// Since mitre does not contain 'lastModified', it might be empty for some stale record.
//
// It use string comparison since all the value in "lastModified" is converted to same time format,
// and empty 'lastModified' is less than 'lastModified' that contains any value when using string comparison,
// which is reasonable when sorting 'lastModified' in descending order.
//
// The first return value shows whether the the cve has been upserted after this function.
func (mdb Mongo) UpsertCPE(ctx context.Context, cpe schema.Cpe) (upserted bool, err error) {
	updateCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	// query: { "cpeName": "...", "lastModified": { "$lte": "<lastModified>" } }
	replaceTarget := bson.D{
		primitive.E{Key: "cpeName", Value: cpe.Name},
		primitive.E{Key: "lastModified", Value: bson.D{primitive.E{Key: "$lte", Value: cpe.LastModified}}},
	}
	cpe.SetParsed()

	upsert, err := mdb.cpe().ReplaceOne(updateCtx, replaceTarget, cpe, options.Replace().SetUpsert(true))
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			mdb.cfg.Logger.Debug(fmt.Sprintf("Latest CPE ID %s in db, not replace", cpe.Name))
			return false, nil
		}
		return false, err
	}

	// cpe in collection has been either inserted or updated
	if upsert.ModifiedCount+upsert.UpsertedCount > 0 {
		return true, nil
	}

	return false, nil
}

// UpsertCPEs upserts CPEs to 'nvd.cpe' collection in batch
func (mdb Mongo) UpsertCPEs(ctx context.Context, cpes []schema.Cpe) (upsertCnt int, err error) {
	upsertBatch := func(start, end int) (batchUpCnt int, err error) {
		updateCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
		defer cancel()
		var models []mongo.WriteModel
		for i := start; i <= end; i++ {
			cpe := cpes[i]
			cpe.SetParsed()
			replaceTarget := bson.D{
				primitive.E{Key: "cpeName", Value: cpe.Name},
				primitive.E{Key: "lastModified", Value: bson.D{primitive.E{Key: "$lte", Value: cpe.LastModified}}},
			}
			models = append(models, mongo.NewReplaceOneModel().SetFilter(replaceTarget).SetReplacement(cpe).SetUpsert(true))
		}
		opts := options.BulkWrite().SetOrdered(true)
		upsert, err := mdb.cpe().BulkWrite(updateCtx, models, opts)
		if err != nil {
			return batchUpCnt, err
		}
		return int(upsert.ModifiedCount + upsert.UpsertedCount), nil
	}

	return execBatch(mdb.cfg.Batch, len(cpes)-1, upsertBatch, mdb.cfg.Logger)
}

// GetCVEByID get CVE by CVEID (E.g., CVE-2001-0131)
//   - When CVE is found in `nvd.cve`: return the detail information of cve
//   - When CVE is not found in `nvd.cve`: return ErrNotFound
func (mdb Mongo) GetCVEByID(ctx context.Context, cveId string) (*schema.Cve, error) {
	getCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	var result schema.Cve
	err := mdb.cve().FindOne(getCtx, bson.D{primitive.E{Key: "cveId", Value: cveId}}).Decode(&result)
	if err != nil {
		// err = mongo.ErrNoDocuments means cve not found in collection
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &result, nil
}

// GetCVEByCPE returns CVE with cpe name
// To query with $regex to the index 'nodes.cpeMatch.criteria' which has relatively poor performance
//
//	{
//	    "configurations": {
//	        "$elemMatch": {
//	            "nodes.cpeMatch.criteria": {
//	                "$regex": "^<cpe name product prefix>"
//	            }
//	        }
//	    }
//	}
//
// To leverage the index 'nodes.cpeMatch.criteriaProductPrefix' generated from us, the query becomes
//
//	{
//	    "configurations": {
//	        "$elemMatch": {
//	            "nodes.cpeMatch.criteriaProductPrefix": {
//	                "$eq": "<cpe name product prefix>"
//	            }
//	        }
//	    }
//	}
func (mdb Mongo) GetCVEByCPE(ctx context.Context, cpeName string, opts ...QueryOptions) (*Result[schema.Cve], error) {
	qCfg, err := GetQueryConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("get query config failed: %w", err)
	}

	getCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	cpeParsed := schema.NewCPEParsed(cpeName)
	if cpeParsed == nil {
		return nil, fmt.Errorf("parse cpeName %s failed", cpeName)
	}

	target := bson.D{primitive.E{
		Key: "configurations", Value: bson.D{primitive.E{
			Key: "$elemMatch", Value: bson.D{primitive.E{
				Key: "nodes.cpeMatch.criteriaProductPrefix", Value: bson.D{primitive.E{
					Key: "$eq", Value: cpeParsed.PrefixToProduct,
				}}}},
		}}},
	}

	// Since there's post filtering after getting the result, we get all the result first,
	// filter the result and then handle pagination.
	getAllQCfg, _ := GetQueryConfig()
	result, err := mongoPaginatedQuery[schema.Cve](getCtx, mdb.cve(), target, getAllQCfg)
	if err != nil {
		return result, err
	}

	// sort by Published desc
	result.Sort(func(i, j int) bool {
		return result.Entries[i].Published > result.Entries[j].Published
	})

	// If incoming query does not specify version ("*" or "-"), not filter result
	if schema.IsAll(cpeParsed.Get(schema.CPEVersion)) {
		pagedResult := result.GetPaginated(qCfg.Start, qCfg.Size)
		if pagedResult.IsPageEnd() {
			return &pagedResult, ErrPageEnd
		}
		return &pagedResult, nil
	}

	// If incoming query specifies version, filter the result to only return with matched version
	filteredResult := result.Filter(func(c schema.Cve) bool {
		return c.Match(*cpeParsed)
	})
	if filteredResult.Total == 0 {
		return result, ErrNotFound
	}

	// handle pagination after filtering
	filteredResultPage := filteredResult.GetPaginated(qCfg.Start, qCfg.Size)
	if filteredResult.IsPageEnd() {
		return &filteredResultPage, ErrPageEnd
	}
	return &filteredResultPage, nil
}

// GetCPEByName get CPE by CPEName (E.g., `cpe:2.3:a:rusqlite_project:rusqlite:0.18.0:*:*:*:*:*:*:*`)
//   - When CPE is found in `nvd.cpe`: return the detail information of cpe
//   - When CPE is not found in `nvd.cpe`: return ErrNotFound
func (mdb Mongo) GetCPEByName(ctx context.Context, cpeName string) (*schema.Cpe, error) {
	getCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	var result schema.Cpe
	err := mdb.cpe().FindOne(getCtx, bson.D{primitive.E{Key: "cpeName", Value: cpeName}}).Decode(&result)
	if err != nil {
		// err = mongo.ErrNoDocuments means cve not found in collection
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &result, nil
}

// GetCPEByMatchString get CPEs by CPEMatchString which is prefix of full CPE 2.3 Name.
//
//	E.g., cpe:2.3:*:Microsoft, cpe:2.3:o:microsoft:windows_10:1511
//
// It matches the value in db based on parsed CPE (schema.CPEParsed) which store each part in different fields.
// For the incoming cpeNameMatchString, we try to match the parts that contains meaningful values ('*' and '-' is excluded),
// and returns with CPEs that matches all of the values.
//
//	E.g. 1, cpeNameMatchString=cpe:2.3:*:Microsoft, matches CPEs with vendor=Microsoft
//	E.g. 2, cpeNameMatchString=cpe:2.3:o:microsoft:windows_10, matches CPEs with part=o, vendor=microsoft and product=windows_10
func (mdb Mongo) GetCPEByMatchString(ctx context.Context, cpeNameMatchString string, opts ...QueryOptions) (*Result[schema.Cpe], error) {
	qParsed := schema.NewCPEParsedMap(cpeNameMatchString)
	if len(qParsed) == 0 {
		return nil, fmt.Errorf("cpe name match string '%s' parsed empty", cpeNameMatchString)
	}
	if !schema.IsSpecific(qParsed[schema.CPEVendor.String()]) {
		return nil, fmt.Errorf("should as least specify vendor. E.g., cpe:2.3:*:Microsoft, cpe:2.3:a:Microsoft")
	}

	qCfg, err := GetQueryConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("get query config failed: %w", err)
	}

	qrys := bson.D{}
	for _, field := range schema.CPEFields {
		fieldName := field.String()
		if val, ok := qParsed[fieldName]; ok && schema.IsSpecific(val) {
			qrys = append(qrys, primitive.E{Key: "cpeNameParsed." + fieldName, Value: val})
		}
	}

	getCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	result, err := mongoPaginatedQuery[schema.Cpe](getCtx, mdb.cpe(), qrys, qCfg)
	if err != nil {
		return result, err
	}

	// sort by Created desc
	result.Sort(func(i, j int) bool {
		if result.Entries[i].Created == nil {
			return true
		}
		if result.Entries[j].Created == nil {
			return false
		}
		return *result.Entries[i].Created > *result.Entries[j].Created
	})

	return result, nil
}

// For how to match with text index in mongo: https://stackoverflow.com/a/23985564.
//   - or:  `{ "$text": { "$search": "rusqlite project" } }`
//   - and: `{ "$text": { "$search": "\"rusqlite\" \"project\"" } }`
//
// Only AND is used based on NVD's logic, while there are 2 kinds of queries depends on value of ExactMatch.
//
// E.g., Val="Hello World"
//   - If `ExactMatch=true`, return with `{ "$text": { "$search": "\"Hello World\"" } }`
//   - If `ExactMatch=false`, return with `{ "$text": { "$search": "\"Hello\" \"World\"" } }`
func (kw Keyword) getQuery() (bson.D, error) {
	var qryKeywords []string
	if kw.ExactMatch {
		qryKeywords = append(qryKeywords, `"`+kw.Val+`"`)
	} else {
		for _, l := range strings.Split(kw.Val, " ") {
			qryKeywords = append(qryKeywords, `"`+l+`"`)
		}
	}
	if len(qryKeywords) == 0 {
		return nil, errors.New("empty keyword")
	}
	return bson.D{primitive.E{
		Key: "$text", Value: bson.D{primitive.E{
			Key: "$search", Value: strings.Join(qryKeywords, " "),
		}},
	}}, nil
}

// GetCVEByKeyword searchs with text index in 'nvd.cve' ('descriptions.value') to find match keyword.
// It is the same as using mongo query
//
//	db.cve.find({ $text: { $search: "<keyword>" } });
//
// Usage:
//
//	// find cves that contains "Hello" AND "World" in Descriptions
//	db.GetCVEByKeyword(ctx, Keyword{Val: "Hello World", ExactMatch: false})
//
//	// find cves that contains "Hello World" in Descriptions
//	db.GetCVEByKeyword(ctx, Keyword{Val: "Hello World", ExactMatch: true})
func (mdb Mongo) GetCVEByKeyword(ctx context.Context, keyword Keyword, opts ...QueryOptions) (*Result[schema.Cve], error) {
	qrys, err := keyword.getQuery()
	if err != nil {
		return nil, err
	}

	qCfg, err := GetQueryConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("get query config failed: %w", err)
	}

	getCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	result, err := mongoPaginatedQuery[schema.Cve](getCtx, mdb.cve(), qrys, qCfg)
	if err != nil {
		return result, err
	}

	// sort by Published desc
	result.Sort(func(i, j int) bool {
		return result.Entries[i].Published > result.Entries[j].Published
	})

	return result, nil
}

// GetCPEByKeyword searchs with text index in 'nvd.cpe' ('titles.title' and 'refs.ref') to find match keyword
// It is the same as using mongo query
//
//	db.cpe.find({ $text: { $search: "<keyword>" } });
//
// Usage:
//
//	// find cpes that contains "Hello" AND "World" in Titles or References
//	db.GetCPEByKeyword(ctx, Keyword{Val: "Hello World", ExactMatch: false})
//
//	// find cpes that contains "Hello World" in Titles or References
//	db.GetCPEByKeyword(ctx, Keyword{Val: "Hello World", ExactMatch: true})
func (mdb Mongo) GetCPEByKeyword(ctx context.Context, keyword Keyword, opts ...QueryOptions) (*Result[schema.Cpe], error) {
	qrys, err := keyword.getQuery()
	if err != nil {
		return nil, err
	}

	qCfg, err := GetQueryConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("get query config failed: %w", err)
	}

	getCtx, cancel := context.WithTimeout(ctx, mdb.cfg.Timeout)
	defer cancel()

	result, err := mongoPaginatedQuery[schema.Cpe](getCtx, mdb.cpe(), qrys, qCfg)
	if err != nil {
		return result, err
	}

	// sort by Created desc
	result.Sort(func(i, j int) bool {
		if result.Entries[i].Created == nil {
			return true
		}
		if result.Entries[j].Created == nil {
			return false
		}
		return *result.Entries[i].Created > *result.Entries[j].Created
	})

	return result, nil
}
