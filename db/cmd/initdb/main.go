package main

import (
	"context"
	"log"
	"os"

	"github.com/namsral/flag"
	"go.uber.org/zap"

	"github.com/shlin168/go-nvd/db"
	"github.com/shlin168/go-nvd/utils"
)

func main() {
	fset := flag.NewFlagSetWithEnvPrefix(os.Args[0], "NVD", flag.ExitOnError)

	dbType := fset.String("db-type", db.MongoDBID, "which db to dump data, only support mongo so far")
	dbUser := fset.String("db-user", "admin", "user name to connect to db")
	dbPwd := fset.String("db-pwd", "admin", "user password to connect to db")
	dbEndpoint := fset.String("db-endpoint", "localhost:27017", "endpoint of db")
	dbTimeout := fset.Duration("db-timeout", db.DefaultTimeout, "timeout of operation to db")

	loglvl := fset.String("loglvl", zap.InfoLevel.String(), "log level")
	fset.Parse(os.Args[1:])

	if len(*dbEndpoint) == 0 {
		log.Fatal("db endpoint should be given by -db-endpoint")
	}
	if *dbTimeout <= 0 {
		log.Fatalf("invalid -db-timeout: %v", *dbTimeout)
	}

	logger, err := utils.GetLoggerFromLvlString(*loglvl)
	if err != nil {
		log.Fatalf("Get logger failed: %v", err)
	}
	defer logger.Sync() // flushes buffer, if any

	logger.Info("Flags",
		zap.String("db-type", *dbType),
		zap.String("db-endpoint", *dbEndpoint),
		zap.Duration("db-timeout", *dbTimeout),
	)

	dbCfg := db.NewConfig()
	dbCfg.Timeout = *dbTimeout
	dbCfg.Logger = logger

	var dbCli db.DB
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
	logger.Info("Init db client", zap.String("type", *dbType))

	if err := dbCli.Init(context.Background()); err != nil {
		log.Fatalf("Init db nvd err: %v", err)
	}
}
