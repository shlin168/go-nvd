package main

import (
	"context"
	"log"
	"os"

	"github.com/namsral/flag"
	"go.uber.org/zap"

	"github.com/shlin168/go-nvd/db"
	"github.com/shlin168/go-nvd/server"
	"github.com/shlin168/go-nvd/utils"
)

func main() {
	fset := flag.NewFlagSetWithEnvPrefix(os.Args[0], "NVD", flag.ExitOnError)

	// service
	lisAddr := fset.String("listen", ":8080", "server listen on # port")
	metricsAddr := fset.String("metric", ":6060", "server metrics listen on # port")

	// db
	dbType := fset.String("db-type", db.MongoDBID, "which db to dump data, only support mongo so far")
	dbUser := fset.String("db-user", "admin", "user name to connect db")
	dbPwd := fset.String("db-pwd", "admin", "user password to connect db")
	dbEndpoint := fset.String("db-endpoint", "localhost:27017", "endpoint of db")
	dbTimeout := fset.Duration("db-timeout", db.DefaultTimeout, "timeout of operation to db")

	// logging
	errloglvl := fset.String("err-loglvl", zap.InfoLevel.String(), "log level for error logger")
	acsloglvl := fset.String("acs-loglvl", zap.InfoLevel.String(), "log level for access logger")

	fset.Parse(os.Args[1:])

	errLogger, err := utils.GetLoggerFromLvlString(*errloglvl)
	if err != nil {
		log.Fatalf("Get logger failed: %v", err)
	}
	defer errLogger.Sync() // flushes buffer, if any

	errLogger.Info("Flags - Server",
		zap.String("listen", *lisAddr),
		zap.String("metrics", *metricsAddr),
		zap.String("err-loglvl", *errloglvl),
		zap.String("acs-loglvl", *acsloglvl),
	)
	errLogger.Info("Flags - DB",
		zap.String("type", *dbType),
		zap.String("endpoint", *dbEndpoint),
		zap.Duration("timeout", *dbTimeout),
	)

	acsLogger, err := utils.GetLoggerFromLvlString(*acsloglvl)
	if err != nil {
		log.Fatalf("Get access logger failed: %v", err)
	}

	// Init DB client
	dbCfg := db.Config{
		Timeout: *dbTimeout,
		Batch:   1,
		Logger:  errLogger,
	}
	if err := dbCfg.Validate(); err != nil {
		log.Fatalf("validate db config err: %v", err)
	}

	var dbCli server.NvdDB
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

	nvdCtrl, err := server.NewNvdController("v1", dbCli)
	if err != nil {
		log.Fatalf("Init nvd controller err: %v", err)
	}

	// Init server and start
	srv, err := server.New(*lisAddr, *metricsAddr,
		server.Controllers([]server.Controller{nvdCtrl}...),
		server.ErrorLogger(errLogger),
		server.AccessLogger(acsLogger),
	)
	if err != nil {
		log.Fatalf("Init server err: %v", err)
	}

	srv.Start(context.Background())
}
