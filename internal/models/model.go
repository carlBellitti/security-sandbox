package models

import "sort"

type ScanOptions struct {
	GitHubEnabled    bool
	Debug            bool
	MockScanResponse bool
	MockRepos        bool
	ProductionMode   bool
	Slack            bool
}

type RepoSummaryForReport struct {
	Portfolio string
	RepoName  string
	AppInfo   string
	Notes     string
	Team      string
	TeamKey   string
	Total     int
	Critical  int
	High      int
	Medium    int
	Low       int
}

type Vulnerability struct {
	CreatedAt        string `json:"createdAt"`
	ResolvedAt       string `json:"resolvedAt"`
	FixedOrDismissed string `json:"fixedOrDismissed"`
	HasPatch         string `json:"hasPatch"`
	Repo             string `json:"repo"`
	Package          string `json:"package"`
	GHSAorID         string `json:"ghsaOrID"`
	CVE              string `json:"cve"`
	Severity         string `json:"severity"`
	DaysSince        string `json:"daysSince"`
	Source           string `json:"source"`
	URL              string `json:"url"`
	CurrentStatus    string `json:"status"`
	Team             string `json:"team"`
	Org              string `json:"org"`
	RequestedDueDate string `json:"requestedDueDate"`
}

type IncludedRepo struct {
	Org       string `json:"org"`
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	Portfolio string `json:"portfolio"`
	AppInfo   string `json:"appInfo"`
	Notes     string `json:"notes"`
}

type Team struct {
	DisplayName  string `json:"displayName"`
	SlackID      string `json:"slackID"`
	JiraTeamID   string `json:"jiraTeamID"`
	JiraEnabled  bool   `json:"jiraEnabled"`
	SlackEnabled bool   `json:"slackEnabled"`
}

type ConfigData struct {
	Teams          map[string]Team `json:"teams"`
	ReposGitHub    []IncludedRepo  `json:"reposGithub"`
	RepoDictionary map[string]bool
}

type CurrentVulnerabilitySorter []Vulnerability

func (a CurrentVulnerabilitySorter) Len() int      { return len(a) }
func (a CurrentVulnerabilitySorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a CurrentVulnerabilitySorter) Less(i, j int) bool {
	return a[i].CreatedAt < a[j].CreatedAt
}

type ResolvedVulnerabilitySorter []Vulnerability

func (a ResolvedVulnerabilitySorter) Len() int      { return len(a) }
func (a ResolvedVulnerabilitySorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ResolvedVulnerabilitySorter) Less(i, j int) bool {
	return a[i].ResolvedAt > a[j].ResolvedAt
}

type RepoSummaryReportSorter []RepoSummaryForReport

func (a RepoSummaryReportSorter) Len() int      { return len(a) }
func (a RepoSummaryReportSorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a RepoSummaryReportSorter) Less(i, j int) bool {
	return a[i].Portfolio > a[j].Portfolio
}

func CombineResolvedVulnerabilityData(nv map[string]Vulnerability, ev map[string]Vulnerability) map[string]Vulnerability {

	for k, v := range nv {
		ev[k] = v
	}
	return ev
}

func SortCurrentVulnerabilities(vul map[string]Vulnerability) []Vulnerability {
	var vulnerabilities []Vulnerability
	for _, v := range vul {
		vulnerabilities = append(vulnerabilities, v)
	}

	sort.Sort(CurrentVulnerabilitySorter(vulnerabilities))
	return vulnerabilities

}

func SortResolvedVulnerabilities(vul map[string]Vulnerability) []Vulnerability {
	var vulnerabilities []Vulnerability
	for _, v := range vul {
		vulnerabilities = append(vulnerabilities, v)
	}

	sort.Sort(ResolvedVulnerabilitySorter(vulnerabilities))
	return vulnerabilities

}

func SortRepoSummaryReportData(d map[string]RepoSummaryForReport) []RepoSummaryForReport {
	var rArr []RepoSummaryForReport
	for _, r := range d {
		rArr = append(rArr, r)
	}
	sort.Sort(RepoSummaryReportSorter(rArr))
	return rArr
}
