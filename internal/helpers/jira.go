package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"security-metrics-action/internal/models"
	"strings"
	"time"
)

const TICKET_NO_FIX_SUMMARY_SUFFIX = "(NO FIX AVAILABLE)"

type JiraApiHelper struct {
	Token  string
	Slack  *Slack
	Logger Logger
}

type Marks struct {
	Type string `json:"type"`
}

type ContentSubSection struct {
	Type  string            `json:"type"`
	Text  string            `json:"text,omitempty"`
	Marks []Marks           `json:"marks,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

type ContentSection struct {
	Type    string              `json:"type"`
	Content []ContentSubSection `json:"content"`
}

type Description struct {
	Type    string           `json:"type"`
	Version int              `json:"version"`
	Content []ContentSection `json:"content"`
}

type JiraPostIssueBodyFields struct {
	Project          map[string]string `json:"project"`
	TicketTitle      string            `json:"summary"`
	IssueType        map[string]string `json:"issuetype"`
	Assignee         map[string]string `json:"assignee"`
	Reporter         map[string]string `json:"reporter"`
	Priority         map[string]string `json:"priority"`
	EngineeringTeam  map[string]string `json:"customfield_24137"`
	RequestedDueDate string            `json:"customfield_24140"`
	DueDate          *string           `json:"duedate"`
	SourceID         string            `json:"customfield_24141"`
	Description      Description       `json:"description"`
}

type JiraPostIssueBody struct {
	Fields JiraPostIssueBodyFields `json:"fields"`
}

func InitializeJIRA(s *Slack, logger Logger) JiraApiHelper {
	jiraApiToken := os.Getenv("JIRA_API_TOKEN")
	if jiraApiToken == "" {
		s.SendSlackErrorMessage("Error Getting JIRA API token", s.SlackStatusChannelID)
		log.Fatal("Error getting JIRA API token.")
	}
	return JiraApiHelper{Token: jiraApiToken, Slack: s, Logger: logger}
}

type CreateResponse struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (J *JiraApiHelper) CreateTickets(openVuls map[string]models.Vulnerability, teamData map[string]models.Team) []string {

	blockedTickets := []string{}
	ticketsAlreadyInJira := J.GetTicketsAlreadyInJira(teamData)
	vuls := J.FilterVulnerabilitiesForJira(openVuls, ticketsAlreadyInJira)
	client := &http.Client{
		CheckRedirect: nil}

	projectID := "13845" //SAUG
	project := map[string]string{"id": projectID}

	issueTypeID := "11637" //(Vulnerability)   //"10001" Story
	issueType := map[string]string{"id": issueTypeID}

	reporterID := "6352ab35e14026a7397e8f7c" //Carl Bellitti
	reporter := map[string]string{"id": reporterID}
	J.Logger.Log("\n---CreateTickets: JIRA tickets to be written---\n")

	for k, v := range vuls {
		noFixSuffix := TICKET_NO_FIX_SUMMARY_SUFFIX
		sendToJira := teamData[v.Team].JiraEnabled
		severity := v.Severity
		if v.HasPatch != "NO" {
			noFixSuffix = ""
		} else {
			J.Logger.Log(fmt.Sprintf("    ---New Vulnerability with NO FIX: %s", k))
		}
		ticketTitle := "Dependabot Alert (" + severity + "): " + v.Repo + noFixSuffix
		assignee := map[string]string{}

		priorityID := getPriorityID(v.Severity)
		priority := map[string]string{"id": priorityID}

		teamID := teamData[v.Team].JiraTeamID
		team := map[string]string{"id": teamID}

		requestedDueDate := v.RequestedDueDate
		sourceID := k

		marks := []Marks{
			{Type: "strong"},
		}
		contentForDescription := []ContentSection{}

		//*********** Source *******************
		contentSubSection := []ContentSubSection{}
		contentSubSectiona := ContentSubSection{
			Type:  "text",
			Text:  "Source: ",
			Marks: marks,
		}
		contentSubSectionb := ContentSubSection{
			Type: "text",
			Text: "Github Dependabot",
		}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection := ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Org *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Organization: ",
			Marks: marks,
		}
		org := v.Org
		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: org,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Repo *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Repository: ",
			Marks: marks,
		}
		repo := v.Repo
		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: repo,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Package *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Package: ",
			Marks: marks,
		}
		pkg := v.Package
		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: pkg,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** GHSA/ID *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "GHSA/ID: ",
			Marks: marks,
		}
		ghsa := v.GHSAorID

		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: ghsa,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Severity *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Severity: ",
			Marks: marks,
		}

		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: severity,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Origin Date *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Origin Date: ",
			Marks: marks,
		}
		oDate := v.CreatedAt[0:10]

		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: oDate,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Fix Version *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Fix Version: ",
			Marks: marks,
		}
		fix := v.HasPatch

		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: fix,
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		//*********** Info Link *******************
		contentSubSectiona = ContentSubSection{
			Type:  "text",
			Text:  "Info: ",
			Marks: marks,
		}
		contentSubSectionb = ContentSubSection{
			Type: "text",
			Text: " ",
		}
		infoUrl := v.URL
		contentSubSectionc := ContentSubSection{
			Type:  "inlineCard",
			Attrs: map[string]string{"url": infoUrl},
		}
		contentSubSectiond := ContentSubSection{
			Type: "text",
			Text: " ",
		}
		contentSubSection = []ContentSubSection{}
		contentSubSection = append(contentSubSection, contentSubSectiona, contentSubSectionb, contentSubSectionc, contentSubSectiond)
		contentSection = ContentSection{
			Type:    "paragraph",
			Content: contentSubSection,
		}
		contentForDescription = append(contentForDescription, contentSection)

		description := Description{
			Type:    "doc",
			Version: 1,
			Content: contentForDescription,
		}

		jiraPostBodyfields := JiraPostIssueBodyFields{
			Project:          project,
			TicketTitle:      ticketTitle,
			IssueType:        issueType,
			Assignee:         assignee,
			Reporter:         reporter,
			Priority:         priority,
			EngineeringTeam:  team,
			DueDate:          nil,
			RequestedDueDate: requestedDueDate,
			SourceID:         sourceID,
			Description:      description,
		}

		jiraPostBody := JiraPostIssueBody{
			Fields: jiraPostBodyfields,
		}

		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(jiraPostBody)
		if err != nil {
			J.Slack.SendSlackErrorMessage("Fatal Error, JIRA unable to encode POST data: "+err.Error(), J.Slack.SlackStatusChannelID)
			log.Fatal(err)
		}
		sendToJira = false //DEBUG
		if sendToJira {

			req, err := http.NewRequest(http.MethodPost, "https://sunlife.atlassian.net/rest/api/3/issue/", &buf)
			if err != nil {
				J.Slack.SendSlackErrorMessage("Fatal Error, JIRA Invalid Request: "+err.Error(), J.Slack.SlackStatusChannelID)
				log.Fatal("Invalid request")
			}

			jiraApiToken := J.Token
			req.Header.Add("Accept", "application/json")
			req.Header.Add("Content-Type", "application/json")
			req.Header.Add("Authorization", "Basic "+jiraApiToken)

			response, err := client.Do(req)
			if err != nil {
				J.Slack.SendSlackErrorMessage("Fatal Error, JIRA make tickets response error "+err.Error(), J.Slack.SlackStatusChannelID)
				log.Fatal("Response Error", err.Error())
			}

			responseData, err := io.ReadAll(response.Body)
			if err != nil {
				J.Slack.SendSlackErrorMessage("Fatal Error, JIRA make tickets Unable to parse response "+err.Error(), J.Slack.SlackStatusChannelID)
				log.Fatal("Fatal ResponseData Error", err)
			}

			createResponse := &CreateResponse{}
			if err := json.Unmarshal(responseData, createResponse); err != nil {
				J.Slack.SendSlackErrorMessage("Fatal Error, JIRA GET unable to unmarshal JSON: "+err.Error(), J.Slack.SlackStatusChannelID)
				log.Fatal(err)
			}

			if v.HasPatch == "NO" {
				blockedTickets = append(blockedTickets, createResponse.Key)
			}

			J.Logger.Log(string(responseData))
		} else {
			J.Logger.Log(fmt.Sprintf("  Tickets-Team: %s, createdAt: %s, Org: %s, repo: %s, package: %s,  Key: %s", v.Team, v.CreatedAt[0:10], v.Org, v.Repo, v.Package, k))
		}

	}

	return blockedTickets
}

func (J *JiraApiHelper) GetTicketsAlreadyInJira(teamData map[string]models.Team) map[string]bool {

	J.Logger.Log("\n---Getting issues already in JIRA---\n")

	ticketMap := map[string]bool{}
	futureBufferInDays := 60
	futureDateString := (time.Now().AddDate(0, 0, futureBufferInDays)).String()[0:10]
	nexPageTokenString := ""
	hasNextPage := true

	for hasNextPage {

		url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+(resolutiondate=null+or+resolutiondate<" + futureDateString + ")+and+status!=Rejected+and+status!=Cancelled&fields=status,customfield_24140,priority,summary,customfield_24137,customfield_24141&maxResults=50" + nexPageTokenString

		issueResponse := J.JiraGetRequest(url)

		for _, i := range issueResponse.Issues {
			J.Logger.Log(fmt.Sprintf("    Ticket: %s, team: %s, VulnerabilityID:%s", i.Key, getTeamKeyFromJiraTeamID(i.Fields.Team.ID, teamData), i.Fields.VulnerabilityID))
			ticketMap[i.Fields.VulnerabilityID] = true
		}
		if issueResponse.NextPageToken != "" {
			nexPageTokenString = "&nextPageToken=" + issueResponse.NextPageToken
		} else {
			hasNextPage = false
		}
	}
	J.Logger.Log(fmt.Sprintf("*************Length of TicketMap: %d", len(ticketMap)))
	return ticketMap
}

func (J *JiraApiHelper) FilterVulnerabilitiesForJira(prodVuls map[string]models.Vulnerability, ticketsAlreadyInJira map[string]bool) map[string]models.Vulnerability {

	jiraVuls := map[string]models.Vulnerability{}
	for k, v := range prodVuls {
		if !ticketsAlreadyInJira[k] {
			jiraVuls[k] = v
		}
	}
	return jiraVuls
}

func getPriorityID(severity string) string {

	priority := map[string]string{"CRITICAL": "11080", "HIGH": "2", "MEDIUM": "3", "MODERATE": "3", "LOW": "4"}
	return priority[severity]
}

type Priority struct {
	Name string `json:"name"`
}

type Status struct {
	Name string `json:"name"`
}

type Team struct {
	ID string `json:"id"`
}

type Fields struct {
	Priority        Priority    `json:"priority"`
	RequestDueDate  string      `json:"customfield_24140"`
	VulnerabilityID string      `json:"customfield_24141"`
	Team            Team        `json:"customfield_24137"`
	Status          Status      `json:"status"`
	Summary         string      `json:"summary"`
	Description     Description `json:"description,omitempty"`
}

type Issue struct {
	Fields Fields `json:"fields"`
	Key    string `json:"key"`
}

type IssueResponse struct {
	Issues        []Issue `json:"issues"`
	NextPageToken string  `json:"nextPageToken,omitempty"`
}

type JiraStats struct {
	PastDue     []Issue
	DueInFuture []Issue
}

func (J *JiraApiHelper) GetSAUGJiraStatsForSlack(teamData map[string]models.Team, ticketsMovedToDoneByVulID map[string]bool) map[string]JiraStats {

	// Do not show stats for all tickets, just those past due or due within the window

	jiraStatsResponse := map[string]JiraStats{}
	J.Logger.Log("\n---GetSAUGJiraStatsForSlack: Getting SAUG issues from JIRA for Slack Stats---\n")

	hasNextPage := true
	nextPageTokenString := ""

	for hasNextPage {
		url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+status!=Done+and+status!=Cancelled+and+status!=Rejected&fields=status,customfield_24140,priority,summary,customfield_24137,customfield_24141" + nextPageTokenString

		issueResponse := J.JiraGetRequest(url)

		for _, i := range issueResponse.Issues {

			J.Logger.Log(fmt.Sprintf("  Tickets Not Done Summary: %s, status: %s, priority: %s, req.date: %s", i.Fields.Summary, i.Fields.Status.Name, i.Fields.Priority.Name, i.Fields.RequestDueDate))
			requestedDueDateAsTime, _ := time.Parse("2006-01-02", i.Fields.RequestDueDate)

			teamID := i.Fields.Team.ID
			teamKey := getTeamKeyFromJiraTeamID(teamID, teamData)

			pd := jiraStatsResponse[teamKey].PastDue
			ds := jiraStatsResponse[teamKey].DueInFuture

			if ticketsMovedToDoneByVulID[i.Fields.VulnerabilityID] {
				continue
			}

			if requestedDueDateAsTime.Before(time.Now()) {
				J.Logger.Log(fmt.Sprintf("  PAST DUE - Summary: %s, status: %s, priority: %s, req.date: %s", i.Fields.Summary, i.Fields.Status.Name, i.Fields.Priority.Name, i.Fields.RequestDueDate))
				pd = append(jiraStatsResponse[teamKey].PastDue, i)
			}
			if requestedDueDateAsTime.After(time.Now()) {
				J.Logger.Log(fmt.Sprintf("  DUE IN FUTURE - Summary: %s, status: %s, priority: %s, req.date: %s", i.Fields.Summary, i.Fields.Status.Name, i.Fields.Priority.Name, i.Fields.RequestDueDate))
				ds = append(jiraStatsResponse[teamKey].DueInFuture, i)
			}
			jiraStatsResponse[teamKey] = JiraStats{PastDue: pd, DueInFuture: ds}
		}
		if issueResponse.NextPageToken != "" {
			nextPageTokenString = "&nextPageToken=" + issueResponse.NextPageToken
		} else {
			hasNextPage = false
		}
	}

	return jiraStatsResponse
}

func (J *JiraApiHelper) GetSGRJiraStatsForSlack(teamData map[string]models.Team) map[string]JiraStats {

	// Do not show stats for all tickets, just those past due or due within the window

	jiraStatsResponse := map[string]JiraStats{}
	J.Logger.Log("\n---GetSGRJiraStatsForSlack: Getting SGR issues from JIRA for Slack Stats---\n")

	hasNextPage := true
	nextPageTokenString := ""

	baseURL := J.GetURLForSGRTicketsNotDone(teamData)
	for hasNextPage {
		url := baseURL + nextPageTokenString

		issueResponse := J.JiraGetRequest(url)

		for _, i := range issueResponse.Issues {

			J.Logger.Log(fmt.Sprintf("  SGR Tickets Not Done Summary: %s, status: %s, priority: %s, req.date: %s", i.Fields.Summary, i.Fields.Status.Name, i.Fields.Priority.Name, i.Fields.RequestDueDate))
			requestedDueDateAsTime, _ := time.Parse("2006-01-02", i.Fields.RequestDueDate)

			teamID := i.Fields.Team.ID
			teamKey := getTeamKeyFromJiraTeamID(teamID, teamData)

			pd := jiraStatsResponse[teamKey].PastDue
			ds := jiraStatsResponse[teamKey].DueInFuture

			if requestedDueDateAsTime.Before(time.Now()) {
				J.Logger.Log(fmt.Sprintf("  PAST DUE - Summary: %s, status: %s, priority: %s, req.date: %s", i.Fields.Summary, i.Fields.Status.Name, i.Fields.Priority.Name, i.Fields.RequestDueDate))
				pd = append(jiraStatsResponse[teamKey].PastDue, i)
			}
			if requestedDueDateAsTime.After(time.Now()) {
				J.Logger.Log(fmt.Sprintf("  DUE IN FUTURE - Summary: %s, status: %s, priority: %s, req.date: %s", i.Fields.Summary, i.Fields.Status.Name, i.Fields.Priority.Name, i.Fields.RequestDueDate))
				ds = append(jiraStatsResponse[teamKey].DueInFuture, i)
			}
			jiraStatsResponse[teamKey] = JiraStats{PastDue: pd, DueInFuture: ds}
		}
		if issueResponse.NextPageToken != "" {
			nextPageTokenString = "&nextPageToken=" + issueResponse.NextPageToken
		} else {
			hasNextPage = false
		}
	}

	return jiraStatsResponse
}

func (J *JiraApiHelper) GetURLForSGRTicketsNotDone(teamData map[string]models.Team) string {

	url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SGR+and+issuetype!=10000+and+(status=10000+or+status=10546+or+status=10412)+and+%22Engineering%20Team%22+in("

	for _, t := range teamData {
		url += t.JiraTeamID + ","
	}
	st := strings.TrimRight(url, ",")
	st += ")&fields=status,customfield_24140,priority,summary,customfield_24137,customfield_24141"
	return st

}

type TicketsTobBeUpdatedOrTransitioned struct {
	Status      string
	IssueKey    string
	Team        string
	Summary     string
	NewPatch    string
	Description Description
}

type GetJiraTicketsToBeMovedToDoneResponse struct {
	TicketsByTeam  map[string][]TicketsTobBeUpdatedOrTransitioned
	TicketsByVulID map[string]bool
}

func (J *JiraApiHelper) GetJiraTicketsToBeMovedToDone(fixedOrDismissedVulsMap map[string]bool, openMap map[string]bool, teamData map[string]models.Team) GetJiraTicketsToBeMovedToDoneResponse {

	J.Logger.Log("\n---GetJiraTicketsNotYetDoneButFixedOrDismissed:Tickets With a Patch Detected Not Done, Blocked, Rejected or Cancelled But Fixed/Dismissed or Not found in open list---\n")

	jiraTixNotDoneButFixed := map[string][]TicketsTobBeUpdatedOrTransitioned{}
	ticketsByVulID := map[string]bool{}
	hasNextPage := true
	nextPageTokenString := ""

	for hasNextPage {

		url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+status!=Blocked+and+status!=Done+and+status!=Cancelled+and+status!=Rejected&fields=status,customfield_24140,priority,summary,customfield_24137,customfield_24141" + nextPageTokenString

		issueResponse := J.JiraGetRequest(url)

		for _, i := range issueResponse.Issues {
			id := i.Fields.VulnerabilityID
			id2 := id
			if strings.HasPrefix(id, "GH") {
				id2 = strings.TrimPrefix(id2, "GH")
				id2 = "Dependabot" + id2
			}
			if strings.HasPrefix(id, "Dependabot") {
				id2 = strings.TrimPrefix(id2, "Dependabot")
				id2 = "GH" + id2
			}
			if !openMap[id] && !openMap[id2] && !strings.Contains(i.Fields.Summary, TICKET_NO_FIX_SUMMARY_SUFFIX) {
				team := getTeamKeyFromJiraTeamID(i.Fields.Team.ID, teamData)
				J.Logger.Log(fmt.Sprintf("  Ticket-Key %s, ID: %s, status: %s, team: %s", i.Key, i.Fields.VulnerabilityID, i.Fields.Status.Name, team))
				jiraTixNotDoneButFixed[team] = append(jiraTixNotDoneButFixed[team], TicketsTobBeUpdatedOrTransitioned{IssueKey: i.Key, Status: i.Fields.Status.Name, Team: team, Summary: i.Fields.Summary, Description: i.Fields.Description, NewPatch: "FIXED/DISMISSED"})
				ticketsByVulID[i.Fields.VulnerabilityID] = true
			}
		}
		if issueResponse.NextPageToken != "" {
			nextPageTokenString = "&nextPageToken=" + issueResponse.NextPageToken
		} else {
			hasNextPage = false
		}
	}
	return GetJiraTicketsToBeMovedToDoneResponse{TicketsByTeam: jiraTixNotDoneButFixed, TicketsByVulID: ticketsByVulID}
}

type Transition struct {
	ID string `json:"id"`
}

type JiraPostIssueBodyMoveTicket struct {
	Transition Transition `json:"transition"`
}

func (J *JiraApiHelper) TransitionTicketsToDone(tickets map[string][]TicketsTobBeUpdatedOrTransitioned, teamData map[string]models.Team) {
	J.Logger.Log("\n---TransitionTicketsToDone: Fixed or Dismissed Tickets To be automatically moved to Done Status---\n")
	for team, tMap := range tickets {
		for _, t := range tMap {
			J.Logger.Log(fmt.Sprintf("   Tickets -- key: %s, status: %s, team: %s", t.IssueKey, t.Status, team))
			if !teamData[team].JiraEnabled {
				continue
			}
			J.Logger.Log(fmt.Sprintf("      Moving Ticket to Done -- key: %s", t.IssueKey))
			switch t.Status {
			case "To Do":
				J.ChangeTicketStatus("To Do", t.IssueKey, false)
				fallthrough
			case "In Progress":
				J.ChangeTicketStatus("In Progress", t.IssueKey, false)
				fallthrough
			case "In Testing":
				J.ChangeTicketStatus("In Testing", t.IssueKey, false)
				fallthrough
			case "Ready to Deploy":
				J.ChangeTicketStatus("Ready to Deploy", t.IssueKey, false)
			}
		}
	}
}

func (J *JiraApiHelper) ChangeTicketStatus(currentStatus string, ticketKey string, toBlocked bool) {

	transitions := map[string]string{
		"To Do-to Blocked": "81",  //To Do => Blocked
		"To Do":            "51",  //To Do => In Progress
		"In Progress":      "21",  //In Progress => In Testing
		"In Testing":       "31",  //In Testing => Ready To Deploy
		"Ready to Deploy":  "41",  //Ready To Deploy => Done
		"Blocked":          "121", //Blocked => To Do
	}

	client := &http.Client{
		CheckRedirect: nil}

	var buf bytes.Buffer

	if currentStatus == "To Do" && toBlocked {
		currentStatus += "-to Blocked"
	}

	jiraPostBodyMoveTicket := JiraPostIssueBodyMoveTicket{
		Transition: Transition{ID: transitions[currentStatus]},
	}

	err := json.NewEncoder(&buf).Encode(jiraPostBodyMoveTicket)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA unable to encode POST data: "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://sunlife.atlassian.net//rest/api/3/issue/"+ticketKey+"/transitions", &buf)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA Invalid Request: "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal("Invalid request")
	}

	jiraApiToken := J.Token
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Basic "+jiraApiToken)

	response, err := client.Do(req)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA make tickets response error "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal("Response Error", err.Error())
	}

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA make tickets Unable to parse response "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal("Fatal ResponseData Error", err)
	}
	J.Logger.Log(string(responseData))
}

func (J *JiraApiHelper) GetTicketsThatNowHaveAFix(currentVuls map[string]models.Vulnerability, resolvedIds map[string]bool) []TicketsTobBeUpdatedOrTransitioned {

	tickets := []TicketsTobBeUpdatedOrTransitioned{}

	url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+status=Blocked+and+status!=Done+and+status!=Cancelled+and+status!=Rejected&fields=status,customfield_24140,priority,summary,customfield_24137,customfield_24141,description"

	issueResponse := J.JiraGetRequest(url)

	J.Logger.Log("\n---GetTicketsThatNowHaveAFix: Blocked Tickets Detected With No Fix Available That Now Have a Patch---\n")

	for _, i := range issueResponse.Issues {
		vulID := i.Fields.VulnerabilityID
		if strings.Contains(i.Fields.Summary, TICKET_NO_FIX_SUMMARY_SUFFIX) && currentVuls[vulID].HasPatch != "NO" && !resolvedIds[vulID] {
			J.Logger.Log(fmt.Sprintf("  Tickets to Update with Patch-- %s, Summary: %s, New Patch: %s, vulID: %s", i.Key, i.Fields.Summary, currentVuls[vulID].HasPatch, vulID))
			tickets = append(tickets, TicketsTobBeUpdatedOrTransitioned{IssueKey: i.Key, Summary: i.Fields.Summary, Description: i.Fields.Description, NewPatch: currentVuls[vulID].HasPatch, Team: currentVuls[vulID].Team})
		}
	}
	return tickets
}

type Payload struct {
	Fields map[string]interface{} `json:"fields"`
}

func (J *JiraApiHelper) UpdateIssuesThatNowHaveAFix(tickets []TicketsTobBeUpdatedOrTransitioned, teamData map[string]models.Team) {

	J.Logger.Log("\n---UpdateIssuesThatNowHaveAFix: Tickets Being Updated That now have a fix Available---\n")

	for _, t := range tickets {

		J.Logger.Log(fmt.Sprintf("  Ticket to be Updated with New Patch-- %s, Summary: %s, Team: %s, New Patch: %s", t.IssueKey, t.Summary, t.Team, t.NewPatch))

		if !teamData[t.Team].JiraEnabled {
			continue
		}
		J.Logger.Log(fmt.Sprintf("  ----Ticket being Updated with New Patch-- %s, Summary: %s, Team: %s, New Patch: %s", t.IssueKey, t.Summary, t.Team, t.NewPatch))
		newSummary := strings.TrimSuffix(t.Summary, TICKET_NO_FIX_SUMMARY_SUFFIX)

		updatedDescription := t.Description
		updatedDescription.Content[7].Content[1].Text = t.NewPatch

		descriptionField := updatedDescription

		fields := map[string]interface{}{"summary": newSummary, "description": descriptionField}
		payload := Payload{Fields: fields}

		client := &http.Client{
			CheckRedirect: nil}

		var buf bytes.Buffer
		err := json.NewEncoder(&buf).Encode(payload)

		if err != nil {
			J.Slack.SendSlackErrorMessage("Fatal Error, JIRA unable to encode PUT data: "+err.Error(), J.Slack.SlackStatusChannelID)
			log.Fatal("ENCODER", err)
		}
		fmt.Println(buf.String())
		req, err := http.NewRequest(http.MethodPut, "https://sunlife.atlassian.net/rest/api/3/issue/"+t.IssueKey, &buf)

		if err != nil {
			log.Fatal("Invalid request")
		}

		jiraApiToken := J.Token
		req.Header.Add("Accept", "application/json")
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Basic "+jiraApiToken)

		response, err := client.Do(req)

		if err != nil {
			J.Slack.SendSlackErrorMessage("Fatal Error, JIRA update tickets response error "+err.Error(), J.Slack.SlackStatusChannelID)
			log.Fatal("Response Error", err.Error())
		}

		responseData, err := io.ReadAll(response.Body)

		if err != nil {
			J.Slack.SendSlackErrorMessage("Fatal Error, JIRA update tickets Unable to parse response "+err.Error(), J.Slack.SlackStatusChannelID)
			log.Fatal("Fatal ResponseData Error", err)
		}
		J.Logger.Log(string(responseData))
	}

}

func (J *JiraApiHelper) MoveNewTicketsWithNoFixToBlocked(tickets []string) {
	J.Logger.Log("\n----MoveNewTicketsWithNoFixToBlocked: Tickets with no patch to be moved to Blocked---\n")
	for _, t := range tickets {
		J.Logger.Log(fmt.Sprintf("   Ticket: %s", t))
		J.ChangeTicketStatus("To Do", t, true)
	}
}

func (J *JiraApiHelper) MoveTicketsFromBlockedToToDo(tickets []TicketsTobBeUpdatedOrTransitioned, teamData map[string]models.Team) {
	J.Logger.Log("\n----MoveTicketsFromBlockedToToDo: Tickets to be moved from Blocked to TO DO\n")
	for _, t := range tickets {
		J.Logger.Log(fmt.Sprintf("   Ticket: %s, Team: %s", t.IssueKey, t.Team))
		if teamData[t.Team].JiraEnabled {
			J.ChangeTicketStatus("Blocked", t.IssueKey, false)
		}
	}
}

func (J *JiraApiHelper) JiraGetRequest(url string) IssueResponse {

	client := &http.Client{
		CheckRedirect: nil}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA GET Invalid Request: "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal("Invalid request")
	}

	jiraApiToken := J.Token
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Basic "+jiraApiToken)

	response, err := client.Do(req)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA GET Invalid Request: "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal(err.Error())
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA GET unable to parse response: "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal(err)
	}

	issueResponse := &IssueResponse{}
	if err := json.Unmarshal(body, issueResponse); err != nil {
		J.Slack.SendSlackErrorMessage("Fatal Error, JIRA GET unable to unmarshal JSON: "+err.Error(), J.Slack.SlackStatusChannelID)
		log.Fatal(err)
	}
	//J.Logger.Log(fmt.Sprintf("JIRA GET REQUEST response body: %s", string(body)))

	return *issueResponse
}

func getTeamKeyFromJiraTeamID(teamID string, teamData map[string]models.Team) string {

	for k, v := range teamData {
		if v.JiraTeamID == teamID {
			return k
		}
	}
	return ""
}
