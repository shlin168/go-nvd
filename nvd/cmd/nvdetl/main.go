package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/namsral/flag"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"

	"github.com/shlin168/go-nvd/db"
	"github.com/shlin168/go-nvd/nvd"
	"github.com/shlin168/go-nvd/nvd/schema"
	"github.com/shlin168/go-nvd/utils"
)

const (
	ETLCVE = "cve"
	ETLCPE = "cpe"
)

// NvdUpsertDB is the interface to upsert data from NVD to database
type NvdUpsertDB interface {
	db.DB
	UpsertCVEs(ctx context.Context, cve []schema.Cve) (upsertCnt int, err error)
	UpsertCPEs(ctx context.Context, cpe []schema.Cpe) (upsertCnt int, err error)
}

func main() {
	fset := flag.NewFlagSetWithEnvPrefix(os.Args[0], "NVD", flag.ExitOnError)

	etltype := fset.String("type", "", "mandatory option to decide running etl for 'cpe' or 'cve'")

	dbType := fset.String("db-type", db.MongoDBID, "which db to dump data, only support mongo so far")
	dbUser := fset.String("db-user", "admin", "user name to connect to db")
	dbPwd := fset.String("db-pwd", "admin", "user password to connect to db")
	dbEndpoint := fset.String("db-endpoint", "localhost:27017", "endpoint of db")
	dbTimeout := fset.Duration("db-timeout", db.DefaultTimeout, "timeout of operation to db")

	// 1. dump from stale mtrie foramt of cve data: https://nvd.nist.gov/vuln/data-feeds
	dataFile := fset.String("data", "", "import data file path, support local file or http url")
	prune := fset.Bool("prune", false, "prune the file after importing data to database")
	dltimeout := fset.Duration("dl-timeout", 1*time.Minute, "timeout to download file")

	// 2. dump from api: https://nvd.nist.gov/developers/vulnerabilities
	// utilizes 'sdate' and 'edate' to get CVE/CPEs that have been published or modified between given range of dates
	startDate := fset.String("sdate", time.Now().UTC().Add(0-24*time.Hour).Format("2006-01-02"), "start date when querying nvd api, format: YYYY-MM-DD")
	endDate := fset.String("edate", time.Now().UTC().Format("2006-01-02"), "end date when querying nvd api, format: YYYY-MM-DD")
	apikey := fset.String("apikey", "", "API key for NVD, suggest to provide although it is optional for NVD API")
	waitBetweenReqs := fset.Duration("wait", 5*time.Second, "sleep time between each queries to NVD to avoid hitting rate limit")
	timeout := fset.Duration("timeout", 1*time.Minute, "timeout for nvd api request")

	batch := fset.Int("batch", 10, "batch size when upsert to database")

	loglvl := fset.String("loglvl", zap.InfoLevel.String(), "log level")
	fset.Parse(os.Args[1:])

	if !slices.Contains([]string{ETLCPE, ETLCVE}, *etltype) {
		log.Fatalf("-type is mandatory and expected to by -type=cpe or -type=cve")
	}

	logger, err := utils.GetLoggerFromLvlString(*loglvl)
	if err != nil {
		log.Fatalf("Get logger failed: %v", err)
	}
	defer logger.Sync() // flushes buffer, if any

	logger.Info("Flags",
		zap.String("type", *etltype),
		zap.String("db-type", *dbType),
		zap.String("db-endpoint", *dbEndpoint),
		zap.Duration("db-timeout", *dbTimeout),
		zap.Int("batch", *batch),
	)
	if len(*dataFile) > 0 {
		logger.Info("Flags - from data",
			zap.String("data", *dataFile),
			zap.Bool("prune", *prune),
		)
	} else {
		logger.Info("Flags - from API",
			zap.String("sdate", *startDate),
			zap.String("edate", *endDate),
			zap.Duration("wait", *waitBetweenReqs),
			zap.Duration("timeout", *timeout),
		)
	}

	dbCfg := db.NewConfig()
	dbCfg.Timeout = *dbTimeout
	dbCfg.Batch = *batch
	dbCfg.Logger = logger

	var dbCli NvdUpsertDB
	switch *dbType {
	case db.MongoDBID:
		dbOps := []db.MongoOptions{db.MongoConfig(dbCfg)}
		dbCli, err = db.NewMongo(*dbUser, *dbPwd, *dbEndpoint, dbOps...)
		if err != nil {
			log.Fatalf("Init mongo db client err: %v", err)
		}
		defer dbCli.Disconnect(context.Background())
	default:
		log.Fatalf("unsupported db type: %s", *dbType)
	}
	logger.Info("Init db client")

	if len(*dataFile) > 0 {
		logger.Info("dump from data file")

		finalFile := *dataFile
		if strings.HasPrefix(*dataFile, "http") {
			// CVE: Download file from NVD website, untar and import to database
			// https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2022.json.gz

			// CPE: Download file from NVD website, untar and import to database
			// https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
			dlCli, err := utils.NewGetter(utils.Timeout(*dltimeout))
			if err != nil {
				log.Fatalf("init download client err: %v", err)
			}

			flist := strings.Split(*dataFile, "/")
			dstFilePath := strings.TrimSuffix(filepath.Join("/tmp", flist[len(flist)-1]), ".gz")
			if err := dlCli.Get(context.Background(), *dataFile, dstFilePath); err != nil {
				log.Fatalf("download file err: %v", err)
			}

			finalFile = dstFilePath
			logger.Info("download file", zap.String("from", *dataFile), zap.String("to", dstFilePath))

			if *prune {
				defer func() {
					os.Remove(finalFile)
				}()
			}
		}

		data, err := os.ReadFile(finalFile)
		if err != nil {
			log.Fatalf("read file err: %v", err)
		}

		switch *etltype {
		case ETLCVE:
			var mitre schema.MitreData
			if err := json.Unmarshal(data, &mitre); err != nil {
				log.Fatalf("unmarshal err: %v", err)
			}
			logger.Info(fmt.Sprintf("import %s CVEs, timestamp: %s", mitre.NumberOfCVEs, mitre.Timestamp))

			cves := make([]schema.Cve, len(mitre.Items))
			for i, ci := range mitre.Items {
				newAPICveItem, err := ci.ToAPIStruct()
				if err != nil {
					logger.Warn("get err when parsing " + ci.Cve.CVEDataMeta.ID)
				}
				cves[i] = newAPICveItem.Cve
			}
			upsertedCnt, err := dbCli.UpsertCVEs(context.Background(), cves)
			if err != nil {
				log.Fatalf("upsert cve err: %v", err)
			}
			logger.Info(fmt.Sprintf("upsert %d CVEs", upsertedCnt))
		case ETLCPE:
			var mitre schema.MitreCpeList
			if err := xml.Unmarshal(data, &mitre); err != nil {
				log.Fatalf("unmarshal err: %v", err)
			}
			logger.Info(fmt.Sprintf("import %d CPEs, timestamp: %s", len(mitre.CpeItem), mitre.Generator.Timestamp))

			cpes := make([]schema.Cpe, len(mitre.CpeItem))
			for _, ci := range mitre.CpeItem {
				cpes = append(cpes, ci.ToAPIStruct())
			}
			upsertedCnt, err := dbCli.UpsertCPEs(context.Background(), cpes)
			if err != nil {
				log.Fatalf("upsert cpe err: %v", err)
			}
			logger.Info(fmt.Sprintf("upsert %d CPEs", upsertedCnt))
		}
		return
	}

	if len(*apikey) > 0 {
		logger.Info("dump from API with api key")
	} else {
		logger.Info("dump from API")
	}

	nvcCli, err := nvd.NewClient(
		nvd.APIKey(*apikey),
		nvd.Wait(*waitBetweenReqs),
		nvd.Timeout(*timeout),
		nvd.Logger(logger),
	)
	if err != nil {
		log.Fatalf("init nvd client err: %v", err)
	}

	switch *etltype {
	case ETLCVE:
		rsp, err := nvcCli.GetCVEsInRange(*startDate, *endDate)
		if err != nil {
			log.Fatalf("query nvd err: %v", err)
		}

		logger.Info("get from NVD", zap.Int("result amount", rsp.TotalResults))
		cves := make([]schema.Cve, len(rsp.Items))
		for i, cveItem := range rsp.Items {
			newAPICve := cveItem.Cve
			newAPICve.AddCriteriaProductPrefixs()
			cves[i] = newAPICve
		}
		upsertedCnt, err := dbCli.UpsertCVEs(context.Background(), cves)
		if err != nil {
			log.Fatalf("upsert cve err: %v", err)
		}
		logger.Info(fmt.Sprintf("upsert %d CVEs", upsertedCnt))
	case ETLCPE:
		rsp, err := nvcCli.GetCPEsInRange(*startDate, *endDate)
		if err != nil {
			log.Fatalf("query nvd err: %v", err)
		}

		logger.Info("get from NVD", zap.Int("result amount", rsp.TotalResults))
		cpes := make([]schema.Cpe, len(rsp.Items))
		for i, cpeItem := range rsp.Items {
			newAPICpe := cpeItem.Cpe
			cpes[i] = newAPICpe
		}
		upsertedCnt, err := dbCli.UpsertCPEs(context.Background(), cpes)
		if err != nil {
			log.Fatalf("upsert cpe err: %v", err)
		}
		logger.Info(fmt.Sprintf("upsert %d CPEs", upsertedCnt))
	}
}
