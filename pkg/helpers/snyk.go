package helpers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"test-jira/pkg/config"
	"test-jira/pkg/models"
	"time"
)

type SnykApiHelper struct {
	Token     string
	Slack     *Slack
	OrgID     string
	AppConfig *config.AppConfig
}

type ProjectAttributes struct {
	Name            string  `json:"name"`
	TargetReference *string `json:"target_reference"`
}

type SnykTargets struct {
	ID         string            `json:"id"`
	Attributes ProjectAttributes `json:"attributes"`
}

type TargetAndProjectResponse struct {
	Data []SnykTargets `json:"data"`
}

/******** Issue Response *******/

type SnykResponse struct {
	JSONAPI JSONAPI     `json:"jsonapi"`
	Links   Links       `json:"links"`
	Data    []SnykIssue `json:"data"`
}

type JSONAPI struct {
	Version string `json:"version"`
}

type Links struct {
	Self  string  `json:"self"`
	First string  `json:"first"`
	Last  string  `json:"last"`
	Prev  string  `json:"prev,omitempty"`
	Next  *string `json:"next,omitempty"`
}

type SnykIssue struct {
	ID            string        `json:"id"`
	Type          string        `json:"type"`
	Attributes    Attributes    `json:"attributes"`
	Relationships Relationships `json:"relationships"`
}

type Attributes struct {
	Classes                []Class         `json:"classes,omitempty"`
	Coordinates            []Coordinate    `json:"coordinates"`
	CreatedAt              time.Time       `json:"created_at"`               //MAP - CreatedAt
	EffectiveSeverityLevel string          `json:"effective_severity_level"` //MAP - Severity
	ExploitDetails         *ExploitDetails `json:"exploit_details,omitempty"`
	Ignored                bool            `json:"ignored"`
	Key                    string          `json:"key"` //MAP - GHSAorID
	Problems               []Problem       `json:"problems"`
	Risk                   Risk            `json:"risk"`
	Severities             []Severity      `json:"severities,omitempty"`
	Status                 string          `json:"status"` //MAP - status
	Title                  string          `json:"title"`
	Type                   string          `json:"type"`
	UpdatedAt              time.Time       `json:"updated_at"`
}

type Class struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Type   string `json:"type"`
}

type Coordinate struct {
	IsFixableManually bool             `json:"is_fixable_manually"`
	IsFixableSnyk     bool             `json:"is_fixable_snyk"`
	IsFixableUpstream bool             `json:"is_fixable_upstream"`
	IsPatchable       bool             `json:"is_patchable"` //MAP-HasPatch
	IsPinnable        bool             `json:"is_pinnable"`
	IsUpgradeable     bool             `json:"is_upgradeable"`
	Reachability      string           `json:"reachability"`
	Representations   []Representation `json:"representations"`
}

type Representation struct {
	Dependency Dependency `json:"dependency"`
}

type Dependency struct {
	PackageName    string `json:"package_name"`    //MAP - Package
	PackageVersion string `json:"package_version"` //Map - Concat w/ Package
}

type ExploitDetails struct {
	MaturityLevels []MaturityLevel `json:"maturity_levels"`
	Sources        []string        `json:"sources"`
}

type MaturityLevel struct {
	Format string `json:"format"`
	Level  string `json:"level"`
}

type Problem struct {
	ID        string    `json:"id"` //MAP - CVE ID (need to find it in array)
	Source    string    `json:"source"`
	Type      string    `json:"type"`
	UpdatedAt time.Time `json:"updated_at"`
	URL       string    `json:"url,omitempty"` //MAP - URL (need to find it in array)
}

type Risk struct {
	Factors []string  `json:"factors"`
	Score   RiskScore `json:"score"`
}

type RiskScore struct {
	Model string `json:"model"`
	Value int    `json:"value"`
}

type Severity struct {
	Level            string    `json:"level"`
	ModificationTime time.Time `json:"modification_time"`
	Score            float64   `json:"score"`
	Source           string    `json:"source"`
	Vector           string    `json:"vector"`
	Version          string    `json:"version"`
}

type Relationships struct {
	Organization RelationshipData `json:"organization"`
	ScanItem     RelationshipData `json:"scan_item"`
}

type RelationshipData struct {
	Data  RelatedResource `json:"data"`
	Links RelatedLinks    `json:"links"`
}

type RelatedResource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type RelatedLinks struct {
	Related string `json:"related"`
}

func InitializeSnyk(s *Slack, a *config.AppConfig) SnykApiHelper {
	token := "0446baf8-d20c-4f32-a25a-68fe6c8cc6e3"
	if token == "" {
		log.Fatal("Error getting SNYK API token.")
	}
	return SnykApiHelper{Token: token, Slack: s, AppConfig: a, OrgID: "273207b3-636c-46c5-8e3a-11cc200e9892"}
}

func (S *SnykApiHelper) GetTargetIdsByName(c []models.IncludedRepo, t *[]models.Target) {

	// Do not show stats for all tickets, just those past due or due within the window

	client := &http.Client{
		CheckRedirect: nil}

	for _, r := range c {

		repoName := url.PathEscape(r.Name)

		url := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/targets?version=2024-06-10&limit=100&display_name=" + repoName
		req, err := http.NewRequest(http.MethodGet, url, nil)

		if err != nil {
			log.Fatal("Invalid request")
		}

		token := S.Token
		//log.Println("Token", token)
		req.Header.Add("Authorization", "token "+token)
		req.Header.Add("Content-Type", "application/vnd.api+json")

		response, err := client.Do(req)
		if err != nil {
			log.Fatal(err.Error())
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}

		issueResponse := &TargetAndProjectResponse{}
		if err := json.Unmarshal(body, issueResponse); err != nil {
			log.Fatal(err)
		}

		if len(issueResponse.Data) == 0 {
			S.AppConfig.Logger.Log(fmt.Sprintf("Response Body--------: %s", string(body)))
			continue
		}
		*t = append(*t, models.Target{
			ID:       issueResponse.Data[0].ID,
			Team:     r.Owner,
			RepoName: r.Name,
			Projects: []models.SnykProjects{},
		})
	}
}

func (S *SnykApiHelper) GetProjectIdsFromTargets(t *[]models.Target) {

	temp := *t

	client := &http.Client{
		CheckRedirect: nil}

	for i, tg := range *t {

		url := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/projects?version=2024-06-10&limit=100&target_id=" + tg.ID
		req, err := http.NewRequest(http.MethodGet, url, nil)

		if err != nil {
			log.Fatal("Invalid request")
		}

		token := S.Token
		//log.Println("Token", token)
		req.Header.Add("Authorization", "token "+token)
		req.Header.Add("Content-Type", "application/vnd.api+json")

		response, err := client.Do(req)
		if err != nil {
			log.Fatal(err.Error())
		}

		body, err := io.ReadAll(response.Body)
		if err != nil {
			log.Fatal(err)
		}

		projectResponse := &TargetAndProjectResponse{}
		if err := json.Unmarshal(body, projectResponse); err != nil {
			log.Fatal(err)
		}

		//S.AppConfig.Logger.Log(fmt.Sprintf("Response Body--------: %s", string(body)))

		projects := []models.SnykProjects{}
		for _, p := range projectResponse.Data {
			if p.Attributes.TargetReference == nil || (*p.Attributes.TargetReference != "" && *p.Attributes.TargetReference != "development") {
				continue
			}
			projects = append(projects, models.SnykProjects{ID: p.ID, Name: p.Attributes.Name})
		}
		temp[i] = models.Target{
			ID:       tg.ID,
			Team:     tg.Team,
			RepoName: tg.RepoName,
			Projects: projects,
		}
	}
	*t = temp
}

func (S *SnykApiHelper) GetIssuesByOrgAndProject_original(t []models.Target) map[string][]models.Vulnerability {
	teamVuls := map[string][]models.Vulnerability{}

	client := &http.Client{
		CheckRedirect: nil}
	for _, tg := range t {
		repoName := tg.RepoName
		issues := teamVuls[tg.Team]

		for _, project := range tg.Projects {
			initialIssueCount := len(issues)
			initialURL := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/issues?version=2024-06-10&type=package_vulnerability&limit=100&scan_item.type=project&status=open&scan_item.id=" + project.ID
			url := initialURL
			hasNextPage := true
			for hasNextPage {
				req, err := http.NewRequest(http.MethodGet, url, nil)

				if err != nil {
					log.Fatal("Invalid request")
				}

				token := S.Token
				//log.Println("Token", token)
				req.Header.Add("Authorization", "token "+token)
				req.Header.Add("Content-Type", "application/vnd.api+json")

				response, err := client.Do(req)
				if err != nil {
					log.Fatal(err.Error())
				}

				body, err := io.ReadAll(response.Body)
				if err != nil {
					log.Fatal(err)
				}

				issueResponse := &SnykResponse{}
				if err := json.Unmarshal(body, issueResponse); err != nil {
					log.Fatal(err)
				}
				v := models.Vulnerability{}

				for _, i := range issueResponse.Data {
					hasPatch := "False"
					if len(i.Attributes.Coordinates) > 0 && i.Attributes.Coordinates[0].IsPatchable {
						hasPatch = "true"
					}
					cveID := ""

					l := len(i.Attributes.Problems)
					switch l {
					case 1:
						cveID = i.Attributes.Problems[0].ID
					case 2:
						if strings.Contains(i.Attributes.Problems[0].ID, "CVE") {
							cveID = i.Attributes.Problems[0].ID
						} else if strings.Contains(i.Attributes.Problems[1].ID, "CVE") {
							cveID = i.Attributes.Problems[1].ID
						}
					}

					durationSince := time.Since(i.Attributes.CreatedAt)
					daysSince := int64(durationSince) / 1000000000 / 3600 / 24
					v.CreatedAt = i.Attributes.CreatedAt.String()
					v.ResolvedAt = ""
					v.FixedOrDismissed = ""
					v.HasPatch = hasPatch
					v.Repo = repoName
					v.Package = i.Attributes.Coordinates[0].Representations[0].Dependency.PackageName + "-" + i.Attributes.Coordinates[0].Representations[0].Dependency.PackageVersion
					v.GHSAorID = i.Attributes.Key
					v.CVE = cveID
					v.Severity = strings.ToUpper(i.Attributes.EffectiveSeverityLevel)
					v.DaysSince = strconv.FormatInt(daysSince, 10)
					v.Source = "SNYK"
					v.Team = tg.Team
					v.Org = "Legacy"
					v.RequestedDueDate = getRequestedDueDate(strings.ToUpper(v.Severity), v.CreatedAt)
					issues = append(issues, v)
				}

				if issueResponse.Links.Next != nil {
					url = "https://api.snyk.io" + *issueResponse.Links.Next
					hasNextPage = true
				} else {
					hasNextPage = false
				}
			}
			fmt.Printf("Project Id: %s, Name: %s, Number of issues: %d\n", project.ID, project.Name, len(issues)-initialIssueCount)
		}
		teamVuls[tg.Team] = issues
	}
	return teamVuls
}
func (S *SnykApiHelper) GetIssuesByOrgAndProject(t []models.Target) map[string]models.Vulnerability {
	vuls := map[string]models.Vulnerability{}

	client := &http.Client{
		CheckRedirect: nil}
	for _, tg := range t {
		repoName := tg.RepoName

		for _, project := range tg.Projects {
			//initialIssueCount := len(issues)
			initialURL := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/issues?version=2024-06-10&type=package_vulnerability&limit=100&scan_item.type=project&status=open&scan_item.id=" + project.ID
			url := initialURL
			hasNextPage := true
			for hasNextPage {
				req, err := http.NewRequest(http.MethodGet, url, nil)

				if err != nil {
					log.Fatal("Invalid request")
				}

				token := S.Token
				//log.Println("Token", token)
				req.Header.Add("Authorization", "token "+token)
				req.Header.Add("Content-Type", "application/vnd.api+json")

				response, err := client.Do(req)
				if err != nil {
					log.Fatal(err.Error())
				}

				body, err := io.ReadAll(response.Body)
				if err != nil {
					log.Fatal(err)
				}

				issueResponse := &SnykResponse{}
				if err := json.Unmarshal(body, issueResponse); err != nil {
					log.Fatal(err)
				}
				v := models.Vulnerability{}

				for _, i := range issueResponse.Data {
					hasPatch := "False"
					if len(i.Attributes.Coordinates) > 0 && i.Attributes.Coordinates[0].IsPatchable {
						hasPatch = "true"
					}
					cveID := ""

					l := len(i.Attributes.Problems)
					switch l {
					case 1:
						cveID = i.Attributes.Problems[0].ID
					case 2:
						if strings.Contains(i.Attributes.Problems[0].ID, "CVE") {
							cveID = i.Attributes.Problems[0].ID
						} else if strings.Contains(i.Attributes.Problems[1].ID, "CVE") {
							cveID = i.Attributes.Problems[1].ID
						}
					}

					durationSince := time.Since(i.Attributes.CreatedAt)
					daysSince := int64(durationSince) / 1000000000 / 3600 / 24
					v.CreatedAt = i.Attributes.CreatedAt.String()
					v.ResolvedAt = ""
					v.FixedOrDismissed = ""
					v.HasPatch = hasPatch
					v.Repo = repoName
					v.Package = i.Attributes.Coordinates[0].Representations[0].Dependency.PackageName + "-" + i.Attributes.Coordinates[0].Representations[0].Dependency.PackageVersion
					v.GHSAorID = i.Attributes.Key
					v.CVE = cveID
					v.Severity = strings.ToUpper(i.Attributes.EffectiveSeverityLevel)
					v.DaysSince = strconv.FormatInt(daysSince, 10)
					v.Source = "SNYK"
					v.Team = tg.Team
					v.Org = "Legacy"
					v.RequestedDueDate = getRequestedDueDate(strings.ToUpper(v.Severity), v.CreatedAt)
					vKey := v.Source + "-" + v.Repo + "-" + v.Package + "-" + v.GHSAorID + "-" + v.CVE + "-" + v.CreatedAt[0:10]
					vuls[vKey] = v
				}

				if issueResponse.Links.Next != nil {
					url = "https://api.snyk.io" + *issueResponse.Links.Next
					hasNextPage = true
				} else {
					hasNextPage = false
				}
			}
		}
	}
	return vuls
}

/***** NOT USED
func (S *SnykApiHelper) GetCollections() {

	// Do not show stats for all tickets, just those past due or due within the window

	client := &http.Client{
		CheckRedirect: nil}

	//https://api.snyk.io/rest/orgs/{org_id}/collections

	//url := "https://api.snyk.io/rest/orgs/" + clientId + "/projects?version=2024-06-10"
	url := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/collections?version=2024-06-10"
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		log.Fatal("Invalid request")
	}

	token := S.Token
	log.Println("Token", token)
	req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/vnd.api+json")

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	S.AppConfig.Logger.Log(fmt.Sprintf("Response Body--------: %s", string(body)))

}

func (S *SnykApiHelper) GetProjectsFromCollection(id string) {

	// Do not show stats for all tickets, just those past due or due within the window

	client := &http.Client{
		CheckRedirect: nil}

	//https://api.snyk.io/rest/orgs/{org_id}/collections/{collection_id}/relationships/projects

	url := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/collections/" + id + "/relationships/projects?version=2024-06-10"
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		log.Fatal("Invalid request")
	}

	token := S.Token
	log.Println("Token", token)
	req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/vnd.api+json")

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	S.AppConfig.Logger.Log(fmt.Sprintf("Response Body--------: %s", string(body)))

}

func (S *SnykApiHelper) GetProject(id string) {

	// Do not show stats for all tickets, just those past due or due within the window

	client := &http.Client{
		CheckRedirect: nil}

	//https://api.snyk.io/rest/orgs/{org_id}/collections/{collection_id}/relationships/projects

	url := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/projects/" + id + "?version=2024-06-10"
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		log.Fatal("Invalid request")
	}

	token := S.Token
	log.Println("Token", token)
	req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/vnd.api+json")

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	S.AppConfig.Logger.Log(fmt.Sprintf("Response Body--------: %s", string(body)))

}

func (S *SnykApiHelper) GetCollection(id string) {

	// Do not show stats for all tickets, just those past due or due within the window

	client := &http.Client{
		CheckRedirect: nil}

	//https://api.snyk.io/rest/orgs/{org_id}/collections/{collection_id}/relationships/projects

	url := "https://api.snyk.io/rest/orgs/" + S.OrgID + "/collections/" + id + "?version=2024-06-10"
	req, err := http.NewRequest(http.MethodGet, url, nil)

	if err != nil {
		log.Fatal("Invalid request")
	}

	token := S.Token
	log.Println("Token", token)
	req.Header.Add("Authorization", "token "+token)
	req.Header.Add("Content-Type", "application/vnd.api+json")

	response, err := client.Do(req)
	if err != nil {
		log.Fatal(err.Error())
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	S.AppConfig.Logger.Log(fmt.Sprintf("Response Body--------: %s", string(body)))

}

******/
