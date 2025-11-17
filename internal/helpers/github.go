package helpers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"security-metrics-action/internal/models"
	"strconv"
	"strings"
	"time"
)

type QueryResponseOrg struct {
	Data *OrganizationResponse `json:"data"`
}
type OrganizationResponse struct {
	Organization *RepositoriesResponse `json:"organization"`
}
type RepositoriesResponse struct {
	Repositories *RepositoryConnection `json:"repositories"`
}

type RepositoryConnection struct {
	TotalCount int                 `json:"totalCount"`
	PageInfo   *PageInfoResponse   `json:"pageInfo"`
	Nodes      []*RepositorySimple `json:"nodes"`
}

type RepositorySimple struct {
	Name       string `json:"name"`
	IsDisabled bool   `json:"isDisabled"`
	IsArchived bool   `json:"isArchived"`
}
type QueryResponseRepo struct {
	Data *RepositoryResponse `json:"data"`
}
type Repositories struct {
	TotalCount int               `json:"totalCount"`
	PageInfo   *PageInfoResponse `json:"pageInfo"`
	Nodes      []*Repository     `json:"nodes"`
}
type Repository struct {
	Name                string                                  `json:"name"`
	IsDisabled          bool                                    `json:"isDisabled"`
	IsArchived          bool                                    `json:"isArchived"`
	TotalCount          int                                     `json:"totalCount"`
	PageInfo            *PageInfoResponse                       `json:"pageInfo"`
	VulnerabilityAlerts *RepositoryVulnerabilityAlertConnection `json:"VulnerabilityAlerts"`
}

type PageInfoResponse struct {
	EndCursor   string `json:"endCursor"`
	HasNextPage bool   `json:"hasNextPage"`
}
type RepositoryResponse struct {
	Repository *Repository
}
type RepositoryVulnerabilityAlertConnection struct {
	Nodes    []*RepositoryVulnerabilityAlert `json:"nodes"`
	PageInfo *PageInfoResponse               `json:"pageInfo"`
}
type RepositoryVulnerabilityAlert struct {
	CreatedAt             *time.Time             `json:"createdAt"`
	DismissedAt           *time.Time             `json:"dismissedAt"`
	FixedAt               *time.Time             `json:"fixedAt"`
	DependencyScope       string                 `json:"dependencyScope"`
	State                 string                 `json:"state"`
	SecurityVulnerability *SecurityVulnerability `json:"securityVulnerability"`
}

type SecurityVulnerability struct {
	Package                *SecurityAdvisoryPackage        `json:"package"`
	Severity               string                          `json:"severity"`
	VulnerableVersionRange string                          `json:"vulnerableVersionRange"`
	Advisory               *SecurityAdvisory               `json:"advisory"`
	FirstPatchedVersion    *SecurityAdvisoryPackageVersion `json:"firstPatchedVersion"`
	UpdatedAt              *time.Time                      `json:"updatedAt"`
}

type SecurityAdvisory struct {
	Description string                        `json:"description"`
	Permalink   string                        `json:"permalink"`
	PublishedAt *time.Time                    `json:"publishedAt"`
	Identifiers []*SecurityAdvisoryIdentifier `json:"identifiers"`
}
type SecurityAdvisoryIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
type SecurityAdvisoryPackage struct {
	Name      string `json:"name"`
	EcoSystem string `json:"ecosystem"`
}

type SecurityAdvisoryPackageVersion struct {
	Identifier *string `json:"identifier"`
}

type GitHubApiHelper struct {
	Token  string
	Slack  *Slack
	Logger Logger
}
type GetVulnerabilitiesResponse struct {
	Vulnerabilities map[string]models.Vulnerability
	Repos           []string
}

type VulnerabilityCategories struct {
	OpenVulnerabilities      map[string]models.Vulnerability
	FixedVulnerabilities     map[string]models.Vulnerability
	DismissedVulnerabilities map[string]models.Vulnerability
	FixedOrDismissedMap      map[string]bool
	OpenMap                  map[string]bool
}

type AllVulnerabilitiesResponse struct {
	Production  VulnerabilityCategories
	Development VulnerabilityCategories
}

func InitializeGitHub(slack *Slack, logger Logger) GitHubApiHelper {

	token := os.Getenv("GIT_HUB_TOKEN")
	if token == "" {
		slack.SendSlackErrorMessage("Error Getting GitHub API token", slack.SlackStatusChannelID)
		log.Fatal("Error getting GITHUB API token.")
	}
	return GitHubApiHelper{Token: token, Slack: slack, Logger: logger}
}

func (G *GitHubApiHelper) GetSCAandSastFindings(teamData map[string]models.Team, repos []models.IncludedRepo) AllVulnerabilitiesResponse {

	scaFindings := G.GetScaFindings(teamData, repos)
	sastFindings := G.GetSastFindings(teamData, repos)

	maps.Insert(scaFindings.Production.DismissedVulnerabilities, maps.All(sastFindings.Production.DismissedVulnerabilities))
	maps.Insert(scaFindings.Production.FixedVulnerabilities, maps.All(sastFindings.Production.FixedVulnerabilities))
	maps.Insert(scaFindings.Production.OpenVulnerabilities, maps.All(sastFindings.Production.OpenVulnerabilities))
	maps.Insert(scaFindings.Production.FixedOrDismissedMap, maps.All(sastFindings.Production.FixedOrDismissedMap))
	maps.Insert(scaFindings.Production.OpenMap, maps.All(sastFindings.Production.OpenMap))

	return AllVulnerabilitiesResponse{Production: scaFindings.Production, Development: sastFindings.Development}

}

func (G *GitHubApiHelper) GetScaFindings(teamData map[string]models.Team, repos []models.IncludedRepo) AllVulnerabilitiesResponse {

	G.Logger.Log("\n----Getting GitHub Vulnerabilities---")

	token := G.Token

	developmentVulnerabilities := VulnerabilityCategories{}
	developmentVulnerabilities.DismissedVulnerabilities = map[string]models.Vulnerability{}
	developmentVulnerabilities.FixedVulnerabilities = map[string]models.Vulnerability{}
	developmentVulnerabilities.OpenVulnerabilities = map[string]models.Vulnerability{}
	developmentVulnerabilities.FixedOrDismissedMap = map[string]bool{}
	developmentVulnerabilities.OpenMap = map[string]bool{}
	productionVulnerabilities := VulnerabilityCategories{}
	productionVulnerabilities.DismissedVulnerabilities = map[string]models.Vulnerability{}
	productionVulnerabilities.FixedVulnerabilities = map[string]models.Vulnerability{}
	productionVulnerabilities.OpenVulnerabilities = map[string]models.Vulnerability{}
	productionVulnerabilities.FixedOrDismissedMap = map[string]bool{}
	productionVulnerabilities.OpenMap = map[string]bool{}

	var jsonData = make(map[string]string)
	afterCursor := ""
	hasNext := true
	for _, ir := range repos {
		G.Logger.Log("--" + ir.Org + "-" + ir.Name)
		hasNext = true
		currentPage := 1
		for hasNext {
			currentPage++
			jsonData = map[string]string{
				"query": `
				{
					repository(name: "` + ir.Name + `", owner: "` + ir.Org + `") {
						name
						isDisabled
						isArchived
						vulnerabilityAlerts(first: 50 ` + afterCursor + `) {
							totalCount
							pageInfo {
								endCursor
								hasNextPage
							}
							nodes {
								createdAt
								dismissedAt
								dependencyScope
								fixedAt
								state
								securityVulnerability {
									package {
										name
										ecosystem
									}
									advisory {
										description
										permalink
										publishedAt
										identifiers {
											type
											value
										}
									}
									severity
									vulnerableVersionRange
									firstPatchedVersion {
										identifier
									}
									updatedAt	
								}
							}
						}
					}
				}
			`,
			}
			body := GraphQlResponseHelper(jsonData, token, G.Slack)
			queryResponse := &QueryResponseRepo{}
			if err := json.Unmarshal(body, queryResponse); err != nil {
				G.Slack.SendSlackErrorMessage("Fatal Error, Unable to unmarshal graphQL response from Github API", G.Slack.SlackStatusChannelID)
				log.Fatal(err)
			}
			for _, n := range queryResponse.Data.Repository.VulnerabilityAlerts.Nodes {
				if queryResponse.Data.Repository.IsArchived || queryResponse.Data.Repository.IsDisabled {
					G.Logger.Log(fmt.Sprintf("-----WARNING----- Repository %s is archived or disabled", queryResponse.Data.Repository.Name))
					continue
				}
				VulnerabilityData := VulnerabilityNodeToData(n, queryResponse.Data.Repository.Name, ir.Owner, ir.Org)
				vKey := VulnerabilityData.Source + "-" + VulnerabilityData.Repo + "-" + VulnerabilityData.Package + "-" + VulnerabilityData.GHSAorID + "-" + VulnerabilityData.CVE + "-" + VulnerabilityData.CreatedAt[0:10]
				if strings.Contains(VulnerabilityData.Severity, "DEV") {
					if VulnerabilityData.CurrentStatus == "DISMISSED" {
						developmentVulnerabilities.DismissedVulnerabilities[vKey] = VulnerabilityData
						developmentVulnerabilities.FixedOrDismissedMap[vKey] = true
					} else if VulnerabilityData.CurrentStatus == "FIXED" {
						developmentVulnerabilities.FixedVulnerabilities[vKey] = VulnerabilityData
						developmentVulnerabilities.FixedOrDismissedMap[vKey] = true
					} else if VulnerabilityData.CurrentStatus == "OPEN" {
						developmentVulnerabilities.OpenVulnerabilities[vKey] = VulnerabilityData
						developmentVulnerabilities.OpenMap[vKey] = true
					} else {
						continue
					}
				} else {
					if VulnerabilityData.CurrentStatus == "DISMISSED" {
						productionVulnerabilities.DismissedVulnerabilities[vKey] = VulnerabilityData
						productionVulnerabilities.FixedOrDismissedMap[vKey] = true
					} else if VulnerabilityData.CurrentStatus == "FIXED" {
						productionVulnerabilities.FixedVulnerabilities[vKey] = VulnerabilityData
						productionVulnerabilities.FixedOrDismissedMap[vKey] = true
					} else if VulnerabilityData.CurrentStatus == "OPEN" {
						productionVulnerabilities.OpenVulnerabilities[vKey] = VulnerabilityData
						productionVulnerabilities.OpenMap[vKey] = true
					} else {
						continue
					}
				}
			}

			if queryResponse.Data.Repository.VulnerabilityAlerts.PageInfo.HasNextPage {
				afterCursor = `, after: "` + queryResponse.Data.Repository.VulnerabilityAlerts.PageInfo.EndCursor + `"`
			} else {
				afterCursor = ""
			}
			hasNext = queryResponse.Data.Repository.VulnerabilityAlerts.PageInfo.HasNextPage
		}
	}

	return AllVulnerabilitiesResponse{Production: productionVulnerabilities, Development: developmentVulnerabilities}
}

func VulnerabilityNodeToData(node *RepositoryVulnerabilityAlert, repoName string, repoOwner string, org string) models.Vulnerability {

	var severityAbbreviations = make(map[string]string)
	severityAbbreviations["CRITICAL"] = "CR"
	severityAbbreviations["HIGH"] = "HI"
	severityAbbreviations["MODERATE"] = "MD"
	severityAbbreviations["LOW"] = "LO"
	var v models.Vulnerability
	n := node
	ghsa := "NONE"
	cve := "NONE"
	fixedOrDismissed := ""
	hasPatch := "NO"
	resolvedAt := "N/A"
	for _, i := range n.SecurityVulnerability.Advisory.Identifiers {
		if i.Type == "GHSA" {
			ghsa = i.Value
		}
		if i.Type == "CVE" {
			cve = i.Value
		}
	}

	if n.SecurityVulnerability.FirstPatchedVersion != nil {
		hasPatch = *n.SecurityVulnerability.FirstPatchedVersion.Identifier + " (" + n.SecurityVulnerability.Package.EcoSystem + ")"
	}
	state := node.State
	if (state == "DISMISSED" || state == "AUTO_DISMISSED") && n.DismissedAt != nil {
		resolvedAt = n.DismissedAt.String()[0:10]
		fixedOrDismissed = "DISMISSED"
	}
	if state == "FIXED" && n.FixedAt != nil {
		resolvedAt = n.FixedAt.String()[0:10]
		fixedOrDismissed = "FIXED"
	}

	severity := n.SecurityVulnerability.Severity

	if n.DependencyScope == "DEVELOPMENT" {
		severity = "DEV-" + severityAbbreviations[severity]
	}

	durationSince := time.Since(*n.CreatedAt)
	daysSince := int64(durationSince) / 1000000000 / 3600 / 24
	v.Repo = repoName
	v.Package = n.SecurityVulnerability.Package.Name
	v.CreatedAt = n.CreatedAt.String()
	v.GHSAorID = ghsa
	v.CVE = cve
	v.Severity = severity
	v.DaysSince = strconv.FormatInt(daysSince, 10)
	v.FixedOrDismissed = fixedOrDismissed
	v.HasPatch = hasPatch
	v.ResolvedAt = resolvedAt
	v.Source = "Dependabot"
	v.CurrentStatus = state
	v.URL = n.SecurityVulnerability.Advisory.Permalink
	v.Team = repoOwner
	v.Org = org
	v.RequestedDueDate = getRequestedDueDate(severity, v.CreatedAt)
	return v
}

func GraphQlResponseHelper(jsonData map[string]string, token string, s *Slack) []byte {
	jsonValue, _ := json.Marshal(jsonData)
	req, err := http.NewRequest("POST", "https://api.github.com/graphql", bytes.NewBuffer(jsonValue))
	if err != nil {
		s.SendSlackErrorMessage("Fatal Error, Github call to API failed: "+err.Error(), s.SlackStatusChannelID)
		log.Fatal(err)
	}
	req.SetBasicAuth(token, "x-oauth-basic")

	client := http.Client{}
	res, err := client.Do(req)
	if err != nil {
		s.SendSlackErrorMessage("Fatal Error, Github call to API failed: "+err.Error(), s.SlackStatusChannelID)
		log.Fatal(err)
	}

	// read body
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		s.SendSlackErrorMessage("Fatal Error, Github call to API - response Body: "+err.Error(), s.SlackStatusChannelID)
		log.Fatal(err)
	}
	return body
}

//********************** GITHUB SAST *******************//

type SastApiHelper struct {
	Token  string
	Slack  *Slack
	Logger Logger
}

type SastAlert struct {
	Number              int          `json:"number"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
	URL                 string       `json:"url"`
	HTMLURL             string       `json:"html_url"`
	State               string       `json:"state"`
	FixedAt             *time.Time   `json:"fixed_at"`
	DismissedBy         *User        `json:"dismissed_by"`
	DismissedAt         *time.Time   `json:"dismissed_at"`
	DismissedReason     *string      `json:"dismissed_reason"`
	DismissedComment    *string      `json:"dismissed_comment"`
	Rule                SastRule     `json:"rule"`
	Tool                SastTool     `json:"tool"`
	MostRecentInstance  SastInstance `json:"most_recent_instance"`
	InstancesURL        string       `json:"instances_url"`
	DismissalApprovedBy *User        `json:"dismissal_approved_by"`
	Assignees           []User       `json:"assignees"`
}

type User struct {
	Login     string `json:"login"`
	ID        int    `json:"id"`
	AvatarURL string `json:"avatar_url"`
	URL       string `json:"url"`
	HTMLURL   string `json:"html_url"`
	Type      string `json:"type"`
}

type SastRule struct {
	ID                    string   `json:"id"`
	Severity              string   `json:"severity"`
	Description           string   `json:"description"`
	Name                  string   `json:"name"`
	Tags                  []string `json:"tags"`
	FullDescription       string   `json:"full_description"`
	Help                  string   `json:"help"`
	HelpURI               string   `json:"help_uri"`
	SecuritySeverityLevel string   `json:"security_severity_level"`
}

type SastTool struct {
	Name    string  `json:"name"`
	GUID    *string `json:"guid"`
	Version string  `json:"version"`
}

type SastInstance struct {
	Ref             string       `json:"ref"`
	AnalysisKey     string       `json:"analysis_key"`
	Environment     string       `json:"environment"`
	Category        string       `json:"category"`
	State           string       `json:"state"`
	CommitSHA       string       `json:"commit_sha"`
	Message         SastMessage  `json:"message"`
	Location        SastLocation `json:"location"`
	Classifications []string     `json:"classifications"`
}

type SastMessage struct {
	Text string `json:"text"`
}

type SastLocation struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	StartColumn int    `json:"start_column"`
	EndColumn   int    `json:"end_column"`
}

type SastAlertsResponse []SastAlert

func (G *GitHubApiHelper) GetSastFindings(teamData map[string]models.Team, repos []models.IncludedRepo) AllVulnerabilitiesResponse {
	developmentVulnerabilities := VulnerabilityCategories{}
	developmentVulnerabilities.DismissedVulnerabilities = map[string]models.Vulnerability{}
	developmentVulnerabilities.FixedVulnerabilities = map[string]models.Vulnerability{}
	developmentVulnerabilities.OpenVulnerabilities = map[string]models.Vulnerability{}
	developmentVulnerabilities.FixedOrDismissedMap = map[string]bool{}
	developmentVulnerabilities.OpenMap = map[string]bool{}
	productionVulnerabilities := VulnerabilityCategories{}
	productionVulnerabilities.DismissedVulnerabilities = map[string]models.Vulnerability{}
	productionVulnerabilities.FixedVulnerabilities = map[string]models.Vulnerability{}
	productionVulnerabilities.OpenVulnerabilities = map[string]models.Vulnerability{}
	productionVulnerabilities.FixedOrDismissedMap = map[string]bool{}
	productionVulnerabilities.OpenMap = map[string]bool{}

	for _, ir := range repos {
		team := ir.Owner
		vuls := G.GetSastFindingsForRepo(ir.Org, ir.Name, team)

		for _, v := range vuls {
			vKey := v.Source + "-" + v.Repo + "-" + v.Package + "-" + v.GHSAorID + "-" + v.CVE + "-" + v.CreatedAt[0:10]
			if v.FixedOrDismissed == "" && v.CurrentStatus == "OPEN" {
				productionVulnerabilities.OpenVulnerabilities[vKey] = v
				productionVulnerabilities.OpenMap[vKey] = true
			} else if v.FixedOrDismissed == "FIXED" || v.FixedOrDismissed == "CLOSED" {
				productionVulnerabilities.FixedVulnerabilities[vKey] = v
				productionVulnerabilities.FixedOrDismissedMap[vKey] = true
			} else if v.FixedOrDismissed == "DISMISSED" {
				productionVulnerabilities.DismissedVulnerabilities[vKey] = v
				productionVulnerabilities.FixedOrDismissedMap[vKey] = true
			}

		}
	}

	return AllVulnerabilitiesResponse{Development: developmentVulnerabilities, Production: productionVulnerabilities}
}

func (G *GitHubApiHelper) GetSastFindingsForRepo(org string, repo string, team string) []models.Vulnerability {

	vuls := []models.Vulnerability{}

	client := &http.Client{
		CheckRedirect: nil}

	url := "https://api.github.com/repos/" + org + "/" + repo + "/code-scanning/alerts"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal("Invalid request")
	}

	apiToken := G.Token
	req.Header.Add("Accept", "application/vnd.github+json")
	req.Header.Add("Authorization", "Bearer "+apiToken)
	req.Header.Add("X-Github-Api-Version", "2022-11-28")

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	issueResponse := &SastAlertsResponse{}
	if err := json.Unmarshal(body, issueResponse); err != nil {
		log.Fatal(err)
	}

	for _, cv := range *issueResponse {
		v := models.Vulnerability{}
		fixedOrDismissed := ""
		if cv.State != "open" {
			fixedOrDismissed = strings.ToUpper(cv.State)
		}

		resolvedAt := "N/A"

		switch cv.State {
		case "fixed":
			resolvedAt = cv.FixedAt.String()[0:10]
		case "dismissed":
			resolvedAt = cv.DismissedAt.String()[0:10]
		}

		durationSince := time.Since(cv.CreatedAt)
		daysSince := int64(durationSince) / 1000000000 / 3600 / 24

		v.Repo = repo
		v.Package = cv.MostRecentInstance.Location.Path
		v.CreatedAt = cv.CreatedAt.String()
		v.GHSAorID = cv.Tool.Name + "-" + strconv.Itoa(cv.Number)
		v.CVE = ""
		v.Severity = strings.ToUpper(cv.Rule.SecuritySeverityLevel)
		v.DaysSince = strconv.FormatInt(daysSince, 10)
		v.FixedOrDismissed = fixedOrDismissed
		v.HasPatch = "NO"
		v.ResolvedAt = resolvedAt
		v.Source = cv.Tool.Name
		v.CurrentStatus = strings.ToUpper(cv.State)
		v.URL = cv.Rule.HelpURI
		v.Team = team
		v.Org = org
		v.RequestedDueDate = getRequestedDueDate(v.Severity, v.CreatedAt)
		vuls = append(vuls, v)
	}
	//G.Logger.Log(fmt.Sprintf("CheckMarx GET REQUEST response body: %s", string(body)))
	return vuls
}

func getRequestedDueDate(severity string, createdAt string) string {
	slaInDays := map[string]int64{"CRITICAL": 14, "HIGH": 30, "MEDIUM": 180, "MODERATE": 180, "LOW": 360}
	createdAtAsTime, _ := time.Parse("2006-01-02", createdAt[0:10])
	requestedDueTime := createdAtAsTime.Add(time.Hour * 24 * time.Duration(slaInDays[severity]))
	return requestedDueTime.Format("2006-01-02")
}
