package utils

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DefaultLogger is the default logger among all project with level="INFO"
var DefaultLogger, _ = GetLoggerFromLvl(zap.InfoLevel)

// GetLoggerFromLvlString gets logger with log level string. E.g, "info", "warn", ...
func GetLoggerFromLvlString(loglvl string, opts ...zap.Option) (*zap.Logger, error) {
	zapLoglvl, err := zapcore.ParseLevel(loglvl)
	if err != nil {
		return nil, fmt.Errorf("parse -loglvel failed: %v", err)
	}
	return GetLoggerFromLvl(zapLoglvl, opts...)
}

// GetLoggerFromLvl gets logger with (zapcore.Level)
func GetLoggerFromLvl(loglvl zapcore.Level, opts ...zap.Option) (*zap.Logger, error) {
	logCfg := zap.NewProductionConfig()
	logCfg.Level = zap.NewAtomicLevelAt(loglvl)
	return logCfg.Build(opts...)
}
