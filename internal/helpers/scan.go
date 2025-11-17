package helpers

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"security-metrics-action/internal/mocks"
	"security-metrics-action/internal/models"
	"strconv"
	"strings"
)

func StartScan(scanOptions models.ScanOptions, logger Logger, isProduction bool) {

	isProd := scanOptions.ProductionMode && isProduction
	runMode := "dev"
	if isProd {
		runMode = "production"
	}
	logger.Log("Running...........")

	slack := InitializeSlack(logger)
	jiraApiHelper := InitializeJIRA(slack, logger)
	googHelper := InitializeGoogle(slack, logger)

	configData := getConfigData(isProd, slack)
	lastRunDate := googHelper.GetLastRunTime()
	slack.SendSlackErrorMessage("Running in "+runMode+" mode, last run date from sheet: "+lastRunDate, slack.SlackStatusChannelID)

	var gitHubAllVulnerabilities = AllVulnerabilitiesResponse{}
	var gitHubRepos = []models.IncludedRepo{}
	var allOpenOrActiveVulnerabilitiesSortedArr []models.Vulnerability
	var allResolvedVulnerabilitiesSortedArr []models.Vulnerability
	var gitHubProductionVulnerabilities = VulnerabilityCategories{}
	var gitHubDevelopmentVulnerabilities = VulnerabilityCategories{}

	if scanOptions.GitHubEnabled {
		gitHubApiHelper := InitializeGitHub(slack, logger)
		if scanOptions.MockRepos {
			gitHubRepos = mocks.GetMockConfig().ReposGitHub
		} else {
			gitHubRepos = configData.ReposGitHub
		}
		gitHubAllVulnerabilities = gitHubApiHelper.GetSCAandSastFindings(configData.Teams, gitHubRepos)
		gitHubProductionVulnerabilities = gitHubAllVulnerabilities.Production
		gitHubDevelopmentVulnerabilities = gitHubAllVulnerabilities.Development

	}

	allOpenOrActiveVulnerabilitiesSortedArr = models.SortCurrentVulnerabilities(combineVulnerabilities([]map[string]models.Vulnerability{gitHubDevelopmentVulnerabilities.OpenVulnerabilities, gitHubProductionVulnerabilities.OpenVulnerabilities}))

	allResolvedVulnerabilitiesSortedArr = models.SortResolvedVulnerabilities(combineVulnerabilities([]map[string]models.Vulnerability{gitHubDevelopmentVulnerabilities.DismissedVulnerabilities, gitHubDevelopmentVulnerabilities.FixedVulnerabilities, gitHubProductionVulnerabilities.DismissedVulnerabilities, gitHubProductionVulnerabilities.FixedVulnerabilities}))

	repoReport := getVulnerabilityListForRepoReport(configData.Teams, gitHubRepos, gitHubProductionVulnerabilities.OpenVulnerabilities)

	repoReportSortedArr := models.SortRepoSummaryReportData(repoReport)

	// Add code to update resolved, current and report to Google Drive
	currentFileKey := "current-dev"
	resolvedFileKey := "resolved-dev"
	repoReportFileKey := "repo-report-dev"

	if isProd {
		currentFileKey = "current"
		resolvedFileKey = "resolved"
		repoReportFileKey = "repo-report"
	}

	logger.Log("\n---Updating Google Drive Files---\n")

	fileInfo := googHelper.GetDriveFileInfo()
	csvCurrent := createCSVStringForCurrent(allOpenOrActiveVulnerabilitiesSortedArr, configData.Teams)
	googHelper.UpdateDriveFile(fileInfo[currentFileKey], csvCurrent)
	csvResolved := createCSVStringForResolved(allResolvedVulnerabilitiesSortedArr)
	googHelper.UpdateDriveFile(fileInfo[resolvedFileKey], csvResolved)
	csvRepoReport := createCSVStringForRepoReport(repoReportSortedArr)
	googHelper.UpdateDriveFile(fileInfo[repoReportFileKey], csvRepoReport)

	//Identify and get all JIRA Tickets that were blocked and previously did not have a fix version, but now do
	tickets := jiraApiHelper.GetTicketsThatNowHaveAFix(gitHubProductionVulnerabilities.OpenVulnerabilities, gitHubProductionVulnerabilities.FixedOrDismissedMap)

	// Update the summary and description of the tickets that now have a fix available
	jiraApiHelper.UpdateIssuesThatNowHaveAFix(tickets, configData.Teams)

	// Move the Tickets that previously had no Fix and were blocked to the "To Do" column
	jiraApiHelper.MoveTicketsFromBlockedToToDo(tickets, configData.Teams)

	// Create JIRA tickets for any new open vulnerabilities and return any new tickets without a fix
	newTicketsWithNoFix := jiraApiHelper.CreateTickets(gitHubProductionVulnerabilities.OpenVulnerabilities, configData.Teams)

	//If a new ticket that was created has no fix, move them blocked (array will be filled with Keys for teams that have JIRA enabled)
	jiraApiHelper.MoveNewTicketsWithNoFixToBlocked(newTicketsWithNoFix)

	// Get tickets that are Fixed/Dismissed or not Open that need to be auto transitioned to DONE
	ticketsToBeTransitionedToDone := jiraApiHelper.GetJiraTicketsToBeMovedToDone(gitHubProductionVulnerabilities.FixedOrDismissedMap, gitHubProductionVulnerabilities.OpenMap, configData.Teams)

	// Automatically transition those tickets to a DONE status that are not currently in BLOCKED, DONE, CANCELLED, OR REJECTED status for which the vulnerability is fixed or dismissed
	jiraApiHelper.TransitionTicketsToDone(ticketsToBeTransitionedToDone.TicketsByTeam, configData.Teams)

	// Get SAUG JIRA stats for Slack
	jiraStatsSaug := jiraApiHelper.GetSAUGJiraStatsForSlack(configData.Teams, ticketsToBeTransitionedToDone.TicketsByVulID)

	// Get SGR JIRA Stats for Slack
	jiraStatsSGR := jiraApiHelper.GetSGRJiraStatsForSlack(configData.Teams)

	// Send Slack Messages
	slack.SendTeamSlackMessages(configData.Teams, repoReportSortedArr, lastRunDate, jiraStatsSaug, jiraStatsSGR, ticketsToBeTransitionedToDone.TicketsByTeam, scanOptions.Slack)

	slack.SendSlackErrorMessage("Successfully ran in "+runMode+" mode, last run date from sheet: "+lastRunDate, slack.SlackStatusChannelID)

}

func getVulnerabilityListForRepoReport(teamData map[string]models.Team, ghr []models.IncludedRepo, ghv map[string]models.Vulnerability) map[string]models.RepoSummaryForReport {

	srs := map[string]models.RepoSummaryForReport{}

	for _, k := range ghr {
		sr := models.RepoSummaryForReport{}
		key := "GH-" + k.Name
		sr.RepoName = k.Org + "-" + k.Name
		sr.Team = teamData[k.Owner].DisplayName
		sr.TeamKey = k.Owner
		sr.AppInfo = k.AppInfo
		sr.Portfolio = k.Portfolio
		sr.Notes = k.Notes
		srs[key] = sr
	}

	crTotal := map[string]int{}
	crNew := map[string]int{}
	hiTotal := map[string]int{}
	hiNew := map[string]int{}
	mdTotal := map[string]int{}
	mdNew := map[string]int{}
	loTotal := map[string]int{}
	loNew := map[string]int{}

	for _, v := range ghv {
		daysSinceInt, _ := strconv.Atoi(v.DaysSince)
		key := v.Source + "-" + v.Repo
		severity := v.Severity
		switch severity {
		case "CRITICAL":
			crTotal[key]++
			if daysSinceInt <= 1 {
				crNew[key]++
			}
		case "HIGH":
			hiTotal[key]++
			if daysSinceInt <= 1 {
				hiNew[key]++
			}
		case "MODERATE":
			mdTotal[key]++
			if daysSinceInt <= 1 {
				mdNew[key]++
			}
		case "LOW":
			loTotal[key]++
			if daysSinceInt <= 1 {
				loNew[key]++
			}
		}
		sr := srs[key]
		sr.Critical = crTotal[key]
		sr.High = hiTotal[key]
		sr.Medium = mdTotal[key]
		sr.Low = loTotal[key]
		sr.Total = sr.Critical + sr.High + sr.Medium + sr.Low
		srs[key] = sr
	}
	return srs
}

func combineVulnerabilities(vs []map[string]models.Vulnerability) map[string]models.Vulnerability {
	var cv = make(map[string]models.Vulnerability)
	for _, v := range vs {
		for k, d := range v {
			cv[k] = d
		}
	}
	return cv
}

func createCSVStringForCurrent(cv []models.Vulnerability, teamData map[string]models.Team) string {
	csvString := ""
	for _, v := range cv {
		csvString += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,,,%s\n", v.CreatedAt[0:10], v.Source, v.Repo, v.Package, v.GHSAorID, v.CVE, v.Severity, v.DaysSince, v.HasPatch, v.URL, teamData[v.Team].DisplayName)
	}
	return strings.TrimRight(csvString, "\n")
}

func createCSVStringForResolved(rv []models.Vulnerability) string {
	csvString := ""
	for _, v := range rv {
		csvString += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", v.ResolvedAt, v.Source, v.Repo, v.Package, v.GHSAorID, v.CVE, v.Severity, v.DaysSince, v.FixedOrDismissed, v.CreatedAt[0:10])
	}
	return strings.TrimRight(csvString, "\n")
}

func createCSVStringForRepoReport(rr []models.RepoSummaryForReport) string {
	csvString := ""
	for _, v := range rr {
		csvString += fmt.Sprintf("%s,%s,%s,%s, %s,%d,%d,%d,%d,%d\n", v.Portfolio, v.AppInfo, v.Notes, v.RepoName, v.Team, v.Total, v.Critical, v.High, v.Medium, v.Low)
	}
	return strings.TrimRight(csvString, "\n")
}

type configDataResponse struct {
	ReposGitHub []models.IncludedRepo  `json:"reposGithub"`
	Teams       map[string]models.Team `json:"teams"`
}

func getConfigData(isProd bool, s *Slack) models.ConfigData {

	configFile := "config-dev.json"
	if isProd {
		configFile = "config.json"
	}
	configDataResponse := configDataResponse{}
	repoDictionary := make(map[string]bool)
	resp, err := os.ReadFile(configFile)
	if err != nil {
		s.SendSlackErrorMessage("Error Reading the "+configFile+" file", s.SlackStatusChannelID)
		log.Fatalf("Unable to read the "+configFile+" file: %v", err)
	}

	err = json.Unmarshal(resp, &configDataResponse)
	if err != nil {
		s.SendSlackErrorMessage("Error, unable to marshal the config file", s.SlackStatusChannelID)
		log.Fatalf("Unable to unmarshal config file: %v", err)
	}
	// In addition to the config file reponse, we are adding a dictionary to easily identify what repos are included using a map.
	for _, i := range configDataResponse.ReposGitHub {
		repoDictionary[i.Name] = true
	}
	return models.ConfigData{Teams: configDataResponse.Teams, ReposGitHub: configDataResponse.ReposGitHub, RepoDictionary: repoDictionary}
}
