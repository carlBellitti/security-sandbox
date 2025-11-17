package main

import (
	"os"
	"security-metrics-action/internal/helpers"
	"security-metrics-action/internal/models"
)

const IS_PRODUCTION = true

func main() {

	/* List of argument vars used for testing
	   /*
	   noGH - Will not get vulnerabilities from GH
	   dev - Will output CSV to the dev drive files, reads from live files, and sends slack messages to "carl-test" channel
	   mockData - Will use mock data instead of real data
	   mockRepos - Will use mock repos instead of real ones
	   debug - Used for testing to add code while troubleshooting issues
	   slack - Force Slack
	*/
	logging := true
	logger := helpers.InitializeLogger(logging)

	commandLineOptions := getScanOptions(os.Args)
	helpers.StartScan(commandLineOptions, logger, IS_PRODUCTION)
}

func getScanOptions(args []string) models.ScanOptions {
	c := models.ScanOptions{
		GitHubEnabled:    true,
		ProductionMode:   true,
		Debug:            false,
		MockScanResponse: false,
		MockRepos:        false,
		Slack:            false,
	}

	if len(args) == 1 {
		return c
	}

	for _, p := range args {
		if p == "noGH" {
			c.GitHubEnabled = false
		}
		if p == "debug" {
			c.Debug = true
		}
		if p == "dev" {
			c.ProductionMode = false
		}
		if p == "mockData" {
			c.MockScanResponse = true
		}
		if p == "mockRepos" {
			c.MockRepos = true
		}
		if p == "slack" {
			c.Slack = true
		}
	}
	return c
}
