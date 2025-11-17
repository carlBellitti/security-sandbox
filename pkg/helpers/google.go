package helpers

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"test-jira/pkg/config"

	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

type GoogleHelper struct {
	DriveSrv  *drive.Service
	Slack     *Slack
	AppConfig *config.AppConfig
}

func InitializeGoogle(s *Slack, a *config.AppConfig) GoogleHelper {
	ctx := context.Background()
	b, err := os.ReadFile("credentials.json")
	if err != nil {
		s.SendSlackErrorMessage("Fatal Error, Google - unable to read the initialization JSON file: "+err.Error(), s.SlackStatusChannelID)
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	srv, err := drive.NewService(ctx, option.WithCredentialsJSON(b))
	if err != nil {
		s.SendSlackErrorMessage("Fatal Error, Google - unable to retrieve the drive client: "+err.Error(), s.SlackStatusChannelID)
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}
	return GoogleHelper{DriveSrv: srv, Slack: s, AppConfig: a}
}

func (G *GoogleHelper) UpdateDriveFile(dfInfo DriveFileInfo, contents string) {

	var df *drive.File
	r := strings.NewReader(contents)

	_, err := G.DriveSrv.Files.Update(dfInfo.ID, df).Media(r).Do()
	if err != nil {
		G.Slack.SendSlackErrorMessage("Fatal Error, Google- unable to update the drive file: "+err.Error(), G.Slack.SlackStatusChannelID)
		log.Fatalf("Unable to Update drive file: %v", err)
	}
	G.AppConfig.Logger.Log(fmt.Sprintf("Drive file %s updated", dfInfo.Name))
}

type DriveFileInfo struct {
	ID   string
	Name string
}

func (G *GoogleHelper) GetDriveFileInfo() map[string]DriveFileInfo {
	fileInfo := map[string]DriveFileInfo{}
	r, err := G.DriveSrv.Files.List().PageSize(100).
		Fields("nextPageToken, files(id, name)").Do()
	if err != nil {
		G.Slack.SendSlackErrorMessage("Fatal Error, Google- unable to retrieve drive files: "+err.Error(), G.Slack.SlackStatusChannelID)
		log.Fatalf("Unable to retrieve files: %v", err)
	}

	if len(r.Files) == 0 {
		G.AppConfig.Logger.Log("No Google Drive files found.")
	} else {
		for _, i := range r.Files {
			d := DriveFileInfo{}
			d.ID = i.Id
			d.Name = i.Name
			if i.Name == "security-vulnerabilities-resolved-dev.csv" {
				fileInfo["resolved-dev"] = d
			}
			if i.Name == "security-vulnerabilities-resolved.csv" {
				fileInfo["resolved"] = d
			}
			if i.Name == "security-vulnerabilities-current-dev.csv" {
				fileInfo["current-dev"] = d
			}
			if i.Name == "security-vulnerabilities-current.csv" {
				fileInfo["current"] = d
			}
			if i.Name == "security-vulnerabilities-repo-report.csv" {
				fileInfo["repo-report"] = d
			}
			if i.Name == "security-vulnerabilities-repo-report-dev.csv" {
				fileInfo["repo-report-dev"] = d
			}
		}
	}
	return fileInfo
}

func (G *GoogleHelper) GetLastRunTime() string {

	fileInfo := G.GetDriveFileInfo()
	currentFileID := fileInfo["current"].ID

	resp, err := G.DriveSrv.Files.Get(currentFileID).Fields("modifiedTime").Do()
	if err != nil {
		G.Slack.SendSlackErrorMessage("Fatal Error, Google- unable to get the last run date: "+err.Error(), G.Slack.SlackStatusChannelID)
		log.Fatalf("Unable to Get Last Run Date/time: %v", err)
	}
	return resp.ModifiedTime
}
