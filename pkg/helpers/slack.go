package helpers

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"test-jira/pkg/config"
	"test-jira/pkg/models"

	"github.com/slack-go/slack"
)

const SLACK_STATUS_CHANNEL_ID = "C0894SUQ9MH"    //#security-alerts
const SLACK_CHANNEL_CARL_TEST_ID = "C0868BLMEUR" //#carl-test

type Slack struct {
	SlackClient          *slack.Client
	SlackStatusChannelID string
	AppConfig            *config.AppConfig
}

func InitializeSlack(a *config.AppConfig) *Slack {
	token := os.Getenv("SLACK_API_TOKEN")
	if token == "" {
		log.Fatal("Error getting Slack API token.")
	}
	return &Slack{
		SlackClient:          slack.New(token),
		SlackStatusChannelID: SLACK_STATUS_CHANNEL_ID,
		AppConfig:            a,
	}
}

func (S *Slack) SendSlackErrorMessage(message string, channelID string) error {
	ChannelID, timestamp, err := S.SlackClient.PostMessage(channelID, slack.MsgOptionText(message, false))
	if err != nil {
		log.Panicln(err.Error())
		return err
	}
	S.AppConfig.Logger.Log(fmt.Sprintf("  Error/Status Message sent successfully to %s channel at %s", ChannelID, timestamp))
	return nil
}

func (S *Slack) SendSlackMessage(message string, channelID string, team string) error {

	ChannelID, timestamp, err := S.SlackClient.PostMessage(channelID, slack.MsgOptionText(message, false))
	if err != nil {
		S.SendSlackErrorMessage(fmt.Sprintf("Slack Send Message error, channelID: %s", channelID), S.SlackStatusChannelID)
		return err
	} else {
		if ChannelID == SLACK_CHANNEL_CARL_TEST_ID {
			team += "(carl-test)"
		}
		S.AppConfig.Logger.Log(fmt.Sprintf("  Message sent successfully to team: %s channel: %s, at %s", team, ChannelID, timestamp))
	}
	return nil
}

func (S *Slack) SendTeamSlackMessages(teamData map[string]models.Team, repoReport []models.RepoSummaryForReport, lastRunDate string, jiraStatsSAUG map[string]JiraStats, jiraStatsSGR map[string]JiraStats, ticketsMovedToDone map[string][]TicketsTobBeUpdatedOrTransitioned) {

	S.AppConfig.Logger.Log("\n---Sending Slack Messages---\n")
	slackData := convertReportData(repoReport)

	slackMessage := ""

	for team := range teamData {
		slackChannel := SLACK_CHANNEL_CARL_TEST_ID //DEBUG
		// if teamData[team].SlackEnabled && ((time.Now().Weekday().String() == "Monday" || time.Now().Weekday().String() == "Thursday") || S.AppConfig.ScanOptions.Slack) {
		// 	slackChannel = teamData[team].SlackID
		// }
		totals := ""
		slackMessage = ""
		slackMessage = "*Results from Security scan ran on " + string(lastRunDate[0:10]) + "*\n"
		slackMessage += "*" + strings.ToUpper(teamData[team].DisplayName) + "*" + "\n\n"
		tData := slackData[team]
		slackMessage += "*GitHub SCA and SAST Stats*" + "\n"
		for _, tdv := range tData {
			totals = ""
			totals = fmt.Sprintf("`%s` - TOTAL: %d, CRITICAL: %d,HIGH: %d,MEDIUM: %d,LOW: %d", tdv.RepoName, tdv.Total, tdv.Critical, tdv.High, tdv.Medium, tdv.Low) + "\n"
			slackMessage += totals
		}
		slackMessage += "Security Sheet: https://docs.google.com/spreadsheets/d/1Ke8xaDqlyqJp-8HiOEyCNW3TwRtJnQHpjoNSkY7KTNU/edit?usp=sharing\n"

		slackMessage += "\n*Jira Ticket Stats*\n\n"

		saugStats := jiraStatsSAUG[team]

		pastDueSortedSAUG := SortJiraIssuesByRequestedDueDate(saugStats.PastDue)
		dueInFutureSortedSAUG := SortJiraIssuesByRequestedDueDate(saugStats.DueInFuture)

		if len(saugStats.DueInFuture) == 0 && len(saugStats.PastDue) == 0 {
			slackMessage += "NICE!! NO TICKETS IN BACKLOG\n"
		} else {
			if len(saugStats.PastDue) > 0 {
				slackMessage += "TICKETS PAST DUE \n"
				for _, i := range pastDueSortedSAUG {
					noFix := ""
					if strings.Contains(i.Fields.Summary, "NO FIX AVAILABLE") {
						noFix = " - (NO FIX AVAILABLE)"
					}
					slackMessage += fmt.Sprintf("https://sunlife.atlassian.net/browse/%s - %s, Due: %s%s\n", i.Key, i.Fields.Priority.Name, i.Fields.RequestDueDate, noFix)
				}
			}
			if len(saugStats.DueInFuture) > 0 {
				slackMessage += "TICKETS DUE IN FUTURE\n"
				for _, i := range dueInFutureSortedSAUG {
					noFix := ""
					if strings.Contains(i.Fields.Summary, "NO FIX AVAILABLE") {
						noFix = " - (NO FIX AVAILABLE)"
					}
					slackMessage += fmt.Sprintf("https://sunlife.atlassian.net/browse/%s - %s, Due: %s%s\n", i.Key, i.Fields.Priority.Name, i.Fields.RequestDueDate, noFix)
				}
			}

		}
		if len(ticketsMovedToDone[team]) > 0 {
			slackMessage += "\n*Jira Tickets that have automatically transitioned to `DONE` status beacuse the vulnerability has been fixed/dismissed*\n"
			for _, t := range ticketsMovedToDone[team] {
				slackMessage += fmt.Sprintf("https://sunlife.atlassian.net/browse/%s\n", t.IssueKey)
			}
			slackMessage += "\n"
		}
		slackMessage += "JIRA Board Link: https://sunlife.atlassian.net/jira/software/c/projects/SAUG/boards/9207\n\n"

		slackMessage += "*SGR Items Stats(PEN Test findings etc.)*\n\n"
		sgrStats := jiraStatsSGR[team]

		pastDueSortedSGR := SortJiraIssuesByRequestedDueDate(sgrStats.PastDue)
		dueInFutureSortedSGR := SortJiraIssuesByRequestedDueDate(sgrStats.DueInFuture)

		if len(sgrStats.DueInFuture) == 0 && len(sgrStats.PastDue) == 0 {
			slackMessage += "NICE!! NO TICKETS IN BACKLOG\n"
		} else {
			if len(sgrStats.PastDue) > 0 {
				slackMessage += "TICKETS PAST DUE \n"
				for _, i := range pastDueSortedSGR {
					noFix := ""
					if strings.Contains(i.Fields.Summary, "NO FIX AVAILABLE") {
						noFix = " - (NO FIX AVAILABLE)"
					}
					slackMessage += fmt.Sprintf("https://sunlife.atlassian.net/browse/%s - %s, Due: %s%s\n", i.Key, i.Fields.Priority.Name, i.Fields.RequestDueDate, noFix)
				}
			}
			if len(sgrStats.DueInFuture) > 0 {
				slackMessage += "TICKETS DUE IN FUTURE\n"
				for _, i := range dueInFutureSortedSGR {
					noFix := ""
					if strings.Contains(i.Fields.Summary, "NO FIX AVAILABLE") {
						noFix = " - (NO FIX AVAILABLE)"
					}
					slackMessage += fmt.Sprintf("https://sunlife.atlassian.net/browse/%s - %s, Due: %s%s\n", i.Key, i.Fields.Priority.Name, i.Fields.RequestDueDate, noFix)
				}
			}

		}
		slackMessage += "JIRA Board Link: https://sunlife.atlassian.net/jira/software/c/projects/SGR/boards/2097\n\n"
		S.SendSlackMessage(slackMessage, slackChannel, team)
	}
}

type slackRepoData struct {
	RepoName string
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
}

func convertReportData(repoReport []models.RepoSummaryForReport) map[string][]slackRepoData {
	var returnValue = make(map[string][]slackRepoData)
	var slackData = slackRepoData{}

	for _, r := range repoReport {

		slackData = slackRepoData{RepoName: r.RepoName, Critical: r.Critical, Total: r.Total, High: r.High, Medium: r.Medium, Low: r.Low}

		returnValue[r.TeamKey] = append(returnValue[r.TeamKey], slackData)
	}
	return returnValue

}

type JiraIssueSorter []Issue

func (a JiraIssueSorter) Len() int      { return len(a) }
func (a JiraIssueSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a JiraIssueSorter) Less(i, j int) bool {
	return a[i].Fields.RequestDueDate < a[j].Fields.RequestDueDate
}

func SortJiraIssuesByRequestedDueDate(issues []Issue) []Issue {
	sort.Sort(JiraIssueSorter(issues))
	return issues

}
