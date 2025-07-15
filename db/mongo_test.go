package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"

	"github.com/shlin168/go-nvd/nvd/schema"
)

const (
	cveCltName = DBNvd + "." + CltCve
	cpeCltName = DBNvd + "." + CltCpe
)

func toBsonD(v interface{}) (doc *bson.D, err error) {
	data, err := bson.Marshal(v)
	if err != nil {
		return
	}

	err = bson.Unmarshal(data, &doc)
	return
}

func TestMongo(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()

	mt.Run("Init", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		assert.Equal(t, DefaultTimeout, cli.cfg.Timeout)
		assert.NotNil(t, cli.cfg.Logger)
		assert.Equal(t, "mongodb://user:pwd@endpoint/nvd?authSource=admin", cli.getURI("user", "pwd", "endpoint"))

		cfg := NewConfig()
		cfg.Timeout = 10 * time.Second
		cli, err = NewMongo("", "", "", MongoTestClient(mt.Client), MongoConfig(cfg))
		require.NoError(t, err)

		assert.Equal(t, 10*time.Second, cli.cfg.Timeout)

		// invalid config
		cfg.Timeout = 0
		_, err = NewMongo("", "", "", MongoConfig(cfg))
		assert.Error(t, err)
	})
}

func TestMongoNvdCVE(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()

	mt.Run("UpsertCVE", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// successfully replace
		mt.AddMockResponses(bson.D{
			primitive.E{Key: "ok", Value: 1},
			primitive.E{Key: "n", Value: 0},          // Number of documents matched.
			primitive.E{Key: "nModified", Value: 1}}, // Number of documents modified.
		// there's also 'upserted' response by mongo while we don't need this value
		)
		upserted, err := cli.UpsertCVE(context.Background(), schema.Cve{CVEID: "CVE-2006-3240"})
		assert.NoError(t, err)
		assert.True(t, upserted)

		// same cveID with latest lastModified exist, not replace
		mt.AddMockResponses(bson.D{
			primitive.E{Key: "ok", Value: 1},
			primitive.E{Key: "n", Value: 1},
			primitive.E{Key: "nModified", Value: 0}},
		)
		upserted, err = cli.UpsertCVE(context.Background(), schema.Cve{CVEID: "CVE-2006-3240"})
		assert.NoError(t, err)
		assert.False(t, upserted)

		// error
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))
		_, err = cli.UpsertCVE(context.Background(), schema.Cve{CVEID: "CVE-2006-3240"})
		require.Error(t, err)
		assert.ErrorContains(t, err, "command failed")
	})

	mt.Run("UpsertCVEs", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// successfully replace
		// there's also 'upserted' response by update operation while we don't need this value
		mt.AddMockResponses(
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},          // Number of documents matched.
				primitive.E{Key: "nModified", Value: 1}}, // Number of documents modified.
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},
				primitive.E{Key: "nModified", Value: 1}},
		)
		upsertedCnt, err := cli.UpsertCVEs(context.Background(), []schema.Cve{{CVEID: "CVE-2006-3240"}, {CVEID: "CVE-2006-3241"}})
		assert.NoError(t, err)
		assert.Equal(t, 2, upsertedCnt)

		// same cveID with latest lastModified exist, not replace
		mt.AddMockResponses(
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},          // Number of documents matched.
				primitive.E{Key: "nModified", Value: 0}}, // Number of documents modified.
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},
				primitive.E{Key: "nModified", Value: 1}},
		)
		upsertedCnt, err = cli.UpsertCVEs(context.Background(), []schema.Cve{{CVEID: "CVE-2006-3240"}, {CVEID: "CVE-2006-3241"}})
		assert.NoError(t, err)
		assert.Equal(t, 1, upsertedCnt)

		// error
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))
		_, err = cli.UpsertCVEs(context.Background(), []schema.Cve{{CVEID: "CVE-2006-3240"}})
		require.Error(t, err)
		assert.ErrorContains(t, err, "command failed")
	})

	mt.Run("mongoPaginatedQuery", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// Mock data for testing
		var cves []schema.Cve
		largeDescription := make([]byte, 1024*1024) // 1MB description to increase document size
		for i := 0; i < 20; i++ {                   // 20 documents with 1MB description each
			id := primitive.NewObjectID() // Generate a new ObjectID for each document
			cves = append(cves, schema.Cve{
				Id:    &id,
				CVEID: fmt.Sprintf("CVE-2022-%04d", 999-i), // Reverse order to test sorting
				Descriptions: []schema.Description{
					{
						Lang:  "en",
						Value: string(largeDescription),
					},
				},
			})
		}

		// The first query's mock response (count query)
		countRsp, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: int64(len(cves))})
		require.NoError(t, err)

		// The second query's mock response (data query)
		var dataRsps []bson.D
		for _, cve := range cves[:10] { // Only return the first 10 items for pagination
			dataRsp, err := toBsonD(cve)
			require.NoError(t, err)
			dataRsps = append(dataRsps, *dataRsp)
		}

		mt.AddMockResponses(
			// First query: count
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *countRsp),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
			// Second query: data
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, dataRsps...),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)

		// Test the mongoPaginatedQuery function
		target := bson.D{primitive.E{Key: "configurations.nodes.cpeMatch.criteriaProductPrefix", Value: "test"}}
		qCfg := QueryConfig{Start: 0, Size: 10}
		result, err := mongoPaginatedQuery[schema.Cve](context.Background(), cli.cve(), target, qCfg)
		require.NoError(t, err)

		// Verify the results
		assert.Equal(t, len(cves), result.Total)
		assert.Equal(t, 10, result.Size)
		for i := 0; i < 10; i++ {
			assert.Equal(t, fmt.Sprintf("CVE-2022-%04d", 999-i), result.Entries[i].CVEID)
		}
	})

	mt.Run("GetCVEByCPE", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// invalid query
		for _, invalidname := range []string{
			"cpe:a:abc",
			"cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*",
			"cpe:2.3:a:dotproject:dotproject:1:2:3:4:5:6:7:8",
		} {
			_, err = cli.GetCVEByCPE(context.Background(), invalidname)
			require.Error(t, err)
		}

		// found
		cpeName := "cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*"

		// The first query's mock response (count query)
		countRsp, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 1})
		require.NoError(t, err)

		// The second query's mock response (data query)
		dataRsp, err := toBsonD(schema.Cve{CVEID: "CVE-2006-3240"})
		require.NoError(t, err)

		mt.AddMockResponses(
			// First query: count
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *countRsp),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
			// Second query: data
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *dataRsp),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		cves, err := cli.GetCVEByCPE(context.Background(), cpeName)
		require.NoError(t, err)
		assert.Equal(t, "CVE-2006-3240", cves.Entries[0].CVEID)

		// command failed
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))

		_, err = cli.GetCVEByCPE(context.Background(), cpeName)
		assert.ErrorContains(t, err, "command failed")

		// cve not found - count query returns empty result
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		_, err = cli.GetCVEByCPE(context.Background(), cpeName)
		assert.ErrorIs(t, err, ErrNotFound)

		// cve not found - count query returns 0
		countRspZero, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 0})
		require.NoError(t, err)

		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *countRspZero),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		_, err = cli.GetCVEByCPE(context.Background(), cpeName)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	mt.Run("GetCVEByID", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// found
		cveId := "CVE-2006-3240"
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, bson.D{primitive.E{Key: "cveId", Value: cveId}}),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		cve, err := cli.GetCVEByID(context.Background(), cveId)
		require.NoError(t, err)
		assert.Equal(t, cveId, cve.CVEID)
		mt.ClearMockResponses()

		// command failed
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))

		_, err = cli.GetCVEByID(context.Background(), cveId)
		assert.ErrorContains(t, err, "command failed")

		// cve not found
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		_, err = cli.GetCVEByID(context.Background(), cveId)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	mt.Run("GetCVEByKeyword", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// found
		cveKeyword := "microsoft"
		result1 := "CVE-2022-0001"
		result2 := "CVE-2022-0002"

		// The first query's mock response (count query)
		countRsp, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 2})
		require.NoError(t, err)

		// The second query's mock response (data query)
		dataRsp1, err := toBsonD(schema.Cve{CVEID: result1})
		require.NoError(t, err)
		dataRsp2, err := toBsonD(schema.Cve{CVEID: result2})
		require.NoError(t, err)

		mt.AddMockResponses(
			// First query: count
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *countRsp),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
			// Second query: data
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *dataRsp1, *dataRsp2),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		cves, err := cli.GetCVEByKeyword(context.Background(), Keyword{Val: cveKeyword})
		require.NoError(t, err)
		assert.Equal(t, result1, cves.Entries[0].CVEID)
		assert.Equal(t, result2, cves.Entries[1].CVEID)
		mt.ClearMockResponses()

		// command failed
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))

		_, err = cli.GetCVEByKeyword(context.Background(), Keyword{Val: cveKeyword})
		assert.ErrorContains(t, err, "command failed")

		// cve not found - count query returns empty result
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		_, err = cli.GetCVEByKeyword(context.Background(), Keyword{Val: cveKeyword})
		assert.ErrorIs(t, err, ErrNotFound)

		// cve not found - count query returns 0
		countRspZero, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 0})
		require.NoError(t, err)

		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cveCltName, mtest.FirstBatch, *countRspZero),
			mtest.CreateCursorResponse(0, cveCltName, mtest.NextBatch),
		)
		_, err = cli.GetCVEByKeyword(context.Background(), Keyword{Val: cveKeyword})
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestMongoNvdCPE(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.Close()

	mt.Run("UpsertCPE", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)
		upsertItem := schema.Cpe{Name: "cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*"}

		// successfully replace
		mt.AddMockResponses(bson.D{
			primitive.E{Key: "ok", Value: 1},
			primitive.E{Key: "n", Value: 0},          // Number of documents matched.
			primitive.E{Key: "nModified", Value: 1}}, // Number of documents modified.
		// there's also 'upserted' response by mongo while we don't need this value
		)
		upserted, err := cli.UpsertCPE(context.Background(), upsertItem)
		assert.NoError(t, err)
		assert.True(t, upserted)

		// same cveID with latest lastModified exist, not replace
		mt.AddMockResponses(bson.D{
			primitive.E{Key: "ok", Value: 1},
			primitive.E{Key: "n", Value: 1},
			primitive.E{Key: "nModified", Value: 0}},
		)
		upserted, err = cli.UpsertCPE(context.Background(), upsertItem)
		assert.NoError(t, err)
		assert.False(t, upserted)

		// error
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))
		_, err = cli.UpsertCPE(context.Background(), upsertItem)
		require.Error(t, err)
		assert.ErrorContains(t, err, "command failed")
	})

	mt.Run("UpsertCPEs", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		upsertItem := schema.Cpe{Name: "cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*"}
		upsertItem2 := schema.Cpe{Name: "cpe:2.3:a:dotproject:dotproject:1.0:*:*:*:*:*:*:*"}

		// successfully replace
		// there's also 'upserted' response by update operation while we don't need this value
		mt.AddMockResponses(
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},          // Number of documents matched.
				primitive.E{Key: "nModified", Value: 1}}, // Number of documents modified.
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},
				primitive.E{Key: "nModified", Value: 1}},
		)
		upsertedCnt, err := cli.UpsertCPEs(context.Background(), []schema.Cpe{upsertItem, upsertItem2})
		assert.NoError(t, err)
		assert.Equal(t, 2, upsertedCnt)

		// same cveID with latest lastModified exist, not replace
		mt.AddMockResponses(
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},          // Number of documents matched.
				primitive.E{Key: "nModified", Value: 0}}, // Number of documents modified.
			bson.D{
				primitive.E{Key: "ok", Value: 1},
				primitive.E{Key: "n", Value: 1},
				primitive.E{Key: "nModified", Value: 1}},
		)
		upsertedCnt, err = cli.UpsertCPEs(context.Background(), []schema.Cpe{upsertItem, upsertItem2})
		assert.NoError(t, err)
		assert.Equal(t, 1, upsertedCnt)

		// error
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))
		_, err = cli.UpsertCPEs(context.Background(), []schema.Cpe{upsertItem, upsertItem2})
		require.Error(t, err)
		assert.ErrorContains(t, err, "command failed")
	})

	mt.Run("GetCPEByName", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// found
		cpeName := "cpe:2.3:a:dotproject:dotproject:*:*:*:*:*:*:*:*"
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, bson.D{primitive.E{Key: "cpeName", Value: cpeName}}),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		cve, err := cli.GetCPEByName(context.Background(), cpeName)
		require.NoError(t, err)
		assert.Equal(t, cpeName, cve.Name)
		mt.ClearMockResponses()

		// command failed
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))

		_, err = cli.GetCPEByName(context.Background(), cpeName)
		assert.ErrorContains(t, err, "command failed")

		// cpe not found
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		_, err = cli.GetCPEByName(context.Background(), cpeName)
		assert.ErrorIs(t, err, ErrNotFound)

	})

	mt.Run("GetCPEByMatchString", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// invalid input
		_, err = cli.GetCPEByMatchString(context.Background(), "not cpe string")
		assert.ErrorContains(t, err, "empty")

		_, err = cli.GetCPEByMatchString(context.Background(), "cpe:2.3:a:*")
		assert.ErrorContains(t, err, "vendor")

		// found
		cpeName := "cpe:2.3:a:dotproject:*:*"
		result1 := "cpe:2.3:a:dotproject:dotproject:1.2:*:*:*:*:*:*:*"
		result2 := "cpe:2.3:a:dotproject:dotproject:1.3:*:*:*:*:*:*:*"

		// The first query's mock response (count query)
		countRsp, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 2})
		require.NoError(t, err)

		// The second query's mock response (data query)
		dataRsp1, err := toBsonD(schema.Cpe{Name: result1})
		require.NoError(t, err)
		dataRsp2, err := toBsonD(schema.Cpe{Name: result2})
		require.NoError(t, err)

		mt.AddMockResponses(
			// First query: count
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, *countRsp),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
			// Second query: data
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, *dataRsp1, *dataRsp2),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		cpes, err := cli.GetCPEByMatchString(context.Background(), cpeName)
		require.NoError(t, err)

		assert.Equal(t, result2, cpes.Entries[0].Name)
		assert.Equal(t, result1, cpes.Entries[1].Name)
		mt.ClearMockResponses()

		// command failed
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))

		_, err = cli.GetCPEByMatchString(context.Background(), cpeName)
		assert.ErrorContains(t, err, "command failed")

		// cpe not found - count query returns empty result
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		_, err = cli.GetCPEByMatchString(context.Background(), cpeName)
		assert.ErrorIs(t, err, ErrNotFound)

		// cpe not found - count query returns 0
		countRspZero, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 0})
		require.NoError(t, err)

		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, *countRspZero),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		_, err = cli.GetCPEByMatchString(context.Background(), cpeName)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	mt.Run("GetCPEByKeyword", func(mt *mtest.T) {
		cli, err := NewMongo("", "", "", MongoTestClient(mt.Client))
		require.NoError(t, err)

		// found
		cpeKeyword := "microsoft 365"
		result1 := "cpe:2.3:a:f-secure:elements_for_microsoft_365:-:*:*:*:*:*:*:*"
		result2 := "cpe:2.3:a:microsoft:365_apps:-:*:*:*:*:*:*:*"

		// The first query's mock response (count query)
		countRsp, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 2})
		require.NoError(t, err)

		// The second query's mock response (data query)
		dataRsp1, err := toBsonD(schema.Cpe{Name: result1})
		require.NoError(t, err)
		dataRsp2, err := toBsonD(schema.Cpe{Name: result2})
		require.NoError(t, err)

		mt.AddMockResponses(
			// First query: count
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, *countRsp),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
			// Second query: data
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, *dataRsp1, *dataRsp2),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		cpes, err := cli.GetCPEByKeyword(context.Background(), Keyword{Val: cpeKeyword})
		require.NoError(t, err)

		assert.Equal(t, result2, cpes.Entries[0].Name)
		assert.Equal(t, result1, cpes.Entries[1].Name)
		mt.ClearMockResponses()

		// command failed
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{}))

		_, err = cli.GetCPEByKeyword(context.Background(), Keyword{Val: cpeKeyword})
		assert.ErrorContains(t, err, "command failed")

		// cpe not found - count query returns empty result
		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		_, err = cli.GetCPEByKeyword(context.Background(), Keyword{Val: cpeKeyword})
		assert.ErrorIs(t, err, ErrNotFound)

		// cpe not found - count query returns 0
		countRspZero, err := toBsonD(struct {
			Count int64 `bson:"count"`
		}{Count: 0})
		require.NoError(t, err)

		mt.AddMockResponses(
			mtest.CreateCursorResponse(1, cpeCltName, mtest.FirstBatch, *countRspZero),
			mtest.CreateCursorResponse(0, cpeCltName, mtest.NextBatch),
		)
		_, err = cli.GetCPEByKeyword(context.Background(), Keyword{Val: cpeKeyword})
		assert.ErrorIs(t, err, ErrNotFound)
	})
}
