package config

import (
	"test-jira/pkg/models"
	"test-jira/pkg/utils"
)

type AppConfig struct {
	ScanOptions  models.ScanOptions
	Logger       utils.Logger
	IsProduction bool
}
