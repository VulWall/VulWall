package logger

import (
	"go.uber.org/zap"
)

var Log *zap.Logger

// Init creates the global logger: JSON in production, console otherwise.
// Logs (including errors) go to stdout so `docker compose logs` shows one
// ordered stream.
func Init(environment string) error {
	cfg := zap.NewDevelopmentConfig()
	if environment == "production" {
		cfg = zap.NewProductionConfig()
	}
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stdout"}

	var err error
	Log, err = cfg.Build()
	return err
}

func Sync() {
	if Log != nil {
		_ = Log.Sync()
	}
}
