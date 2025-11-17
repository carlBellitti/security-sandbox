package main

const CHANNELID = "C0868BLMEUR"

func mainOld() {

	//testGithubSAST()

	// logger := helpers.InitializeLogger(true)
	// slack := helpers.InitializeSlack(logger)
	// msTeams := helpers.InitializeTeams(slack, logger)
	// jiraApiHelper := helpers.InitializeJIRA(slack, logger, msTeams)

	// configData := GetConfigData()
	// jiraSGRStats := jiraApiHelper.GetSGRJiraStatsForMessaging(configData.Teams)
	//msTeams.SendMsTeamsMessages(configData.Teams, stats)

	/*----- Jira Post/Put -------*/
	//resolvedIds := getResolvedIds()
	//ticketsFixed := jiraApiHelper.GetJiraTicketsNotYetDoneButFixed(resolvedIds)
	//jiraApiHelper.MoveFixedTicketsToDone(ticketsFixed)
	//jiraApiHelper.ChangeTicketStatus("In Progress", "SAUG-4")

	/*********************** TESTING *****************
	vul := models.Vulnerability{
		CreatedAt:        "2025-01-17",
		ResolvedAt:       "",
		FixedOrDismissed: "",
		HasPatch:         "com.thoughtworks.xstream:xstream@1.4.11",
		Repo:             "External Applications/slconnect",
		Package:          "com.thoughtworks.xstream:xstream@1.4.10",
		GHSAorID:         "SNYK-JAVA-COMTHOUGHTWORKSXSTREAM-456705",
		CVE:              "CVE-2019-10173",
		Severity:         "CRITICAL",
		DaysSince:        "105",
		Source:           "SNYK",
		URL:              "https://learn.snyk.io/lesson/insecure-deserialization/?authenticate=automatic&_gl=1*1hzvcee*_ga*MTYwNDMxNDcwNC4xNzMwOTg4MTMz*_ga_X9SH3KP7B4*czE3NjI4NzYzOTEkbzkxJGcxJHQxNzYyODc2NDQ3JGo0JGwwJGgw",
		CurrentStatus:    "OPEN",
		Team:             "techbreeze",
		Org:              "Legacy",
		RequestedDueDate: "2025-07-17",
	}
	vuls := map[string]models.Vulnerability{}
	vuls["SNYK-xxx"] = vul
	t := jiraApiHelper.CreateTickets(vuls, configData.Teams)

	fmt.Printf("Response ------ %+v", t) */

	/*----- Jira Issue ----- */
	//issueID := "SGR-1097"
	//jiraApiHelper.GetIssue(issueID)
	//issueResponse := jiraApiHelper.GetIssue(issueID)

	/*----- Jira Issues ----- */

	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+(resolutiondate=null+or+resolutiondate<2025-03-09)&fields=resolutiondate,status,customfield_24137,customfield_24141"
	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SGR+and+status=%22In%20Development%22&fields=resolutiondate,status,customfield_24137,customfield_24141"
	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+status!=Done+and+status!=Cancelled+and+status!=Rejected&fields=resolutiondate,status,customfield_24137,customfield_24141"
	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+status=Cancelled&fields=resolutiondate,status,customfield_24137,customfield_24141"
	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SAUG+and+status!=Done+and+status!=Cancelled+and+status!=Rejected&fields=status,customfield_24140,priority,summary,customfield_24137,customfield_24141,description"
	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SGR+and+(status=10000+or+status=10546+or+status=10412)+and+customfield_24137+in(714601,714602)&fields=resolutiondate,status,customfield_24137,customfield_24141"
	//url := "https://sunlife.atlassian.net/rest/api/3/search/jql?jql=project=SGR+and+(status=10000+or+status=10546+or+status=10412)+and+%22Engineering%20Team%22+in(714601,714602)&fields=resolutiondate,status,customfield_24137,customfield_24141"

	/*-------SGR Items not completed by IT Engineering --------*/
	//configData := GetConfigData()

	/*url := jiraApiHelper.GetURLForSGRTicketsNotDone(configData.Teams)
	issues := jiraApiHelper.GetIssues(url)

	for _, i := range issues.Issues {
		fmt.Println("Issue Key,", i.Key, ",", helpers.GetTeamKeyFromJiraTeamID(i.Fields.Team.ID, configData.Teams))
	} */

	/*-----Jira IssueTypesForProject ----- */
	//id := "SAUG"
	//jiraApiHelper.GetIssueTypesForProject(id)

	/*----- Jira Update Issue ----- */
	//jiraApiHelper.UpdateIssue(issueID, issueResponse, "Version XXXX")

	/*----- Jira Get Tix Already In Jira ----- */

	//configData := GetConfigData()
	//jiraApiHelper.GetTicketsAlreadyInJira(configData.Teams)

	//********************************************* SNYK *********************************/
	//configData := GetConfigData()
	//snykHelper := helpers.InitializeSnyk(slack, logger)
	/*----- SNYK get collections ----- */
	//snykHelper.GetCollections()

	/*----- SNYK get collection By ID ----- */
	//id := "b946b4a0-27fd-4922-baba-04940859a813" // TechBreeze
	//snykHelper.GetCollection(id)

	/*----- SNYK get projects from collection By ID ----- */
	//id := "b946b4a0-27fd-4922-baba-04940859a813" // TechBreeze
	//snykHelper.GetProjectsFromCollection(id)

	/*----- SNYK get project By ID ----- */
	//id := "5320d67b-64f0-4c7c-ae6e-1c86d02fe1d5" //External Applications/slconnect
	//snykHelper.GetProject(id)

	/*----- SNYK get issues by project ID ----- */ ///****************************
	//id := "dfdc2b4f-fa89-4e59-9afe-58fb57884be1"
	//snykHelper.GetIssuesByOrgAndProject()

	/*------------SNYK - Get targets by Name ---------
	targets := []models.Target{}
	snykHelper.GetTargetIdsByName(configData.ReposNonGitHub, &targets)
	snykHelper.GetProjectIdsFromTargets(&targets)
	v := snykHelper.GetIssuesByOrgAndProject(targets)

	t := jiraApiHelper.CreateTickets(v, configData.Teams)

	fmt.Printf("############### JIRA CREATE Response ------ %+v\n", t)

	repoReport := getVulnerabilityListForRepoReport(configData.Teams, configData.ReposNonGitHub, v, "SNYK")
	repoReportSortedArr := models.SortRepoSummaryReportData(repoReport)

	for i, r := range repoReport {
		fmt.Printf("Index: %s, teamKey:%s, Repo: %s, C:%d, H:%d, M:%d, L:%d\n", i, r.TeamKey, r.RepoName, r.Critical, r.High, r.Medium, r.Low)
	}
	msTeams.SendMsTeamsMessages(configData.Teams, jiraSGRStats, repoReportSortedArr) ****/

	//********************************************* Messaging -> Slack *********************************
	/*---- Slack Send Message ----*/
	//slack.SendSlackMessage("test message", "C08JLLXRDEZ", "test")

	//********************************************* Messaging->Teams *********************************
	/*--- Teams Post Message ---*/
	//teamsHelper.PostMessageToChannel()
	//teamsHelper.PostTableToChannel()
}

/*
type ConfigDataResponse struct {
	ReposGitHub    []models.IncludedRepo  `json:"reposGithub"`
	ReposNonGitHub []models.IncludedRepo  `json:"reposNonGithub"`
	ReposAWS       []models.IncludedRepo  `json:"reposAWS"`
	Teams          map[string]models.Team `json:"teams"`
}

func GetConfigData() models.ConfigData {

	configFile := "config.json"

	configDataResponse := ConfigDataResponse{}
	repoDictionary := make(map[string]bool)
	resp, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Unable to read config file: %v", err)
	}

	err = json.Unmarshal(resp, &configDataResponse)
	if err != nil {
		log.Fatalf("Unable to unmarshal config file: %v", err)
	}
	// In addition to the config file reponse, we are adding a dictionary to easily identify what repos are included using a map.
	for _, i := range configDataResponse.ReposAWS {
		repoDictionary[i.Name] = true
	}
	for _, i := range configDataResponse.ReposGitHub {
		repoDictionary[i.Name] = true
	}
	for _, i := range configDataResponse.ReposNonGitHub {
		repoDictionary[i.Name] = true
	}
	return models.ConfigData{Teams: configDataResponse.Teams, ReposGitHub: configDataResponse.ReposGitHub, ReposNonGitHub: configDataResponse.ReposNonGitHub, ReposAWS: configDataResponse.ReposAWS, RepoDictionary: repoDictionary}
}

func getVulnerabilityListForRepoReport(teamData map[string]models.Team, ir []models.IncludedRepo, vu map[string]models.Vulnerability, source string) map[string]models.RepoSummaryForReport {

	srs := map[string]models.RepoSummaryForReport{}

	for _, k := range ir {
		//fmt.Printf("********getVulnerabilityListForRepoReport- repo: %s, owner: %s\n", k.Name, k.Owner)
		sr := models.RepoSummaryForReport{}
		key := source + "-" + k.Name
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

	for _, v := range vu {
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
		case "MEDIUM":
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

func testSnykWithTeamsAndJira() {
	logger := helpers.InitializeLogger(true)
	slack := helpers.InitializeSlack(logger)
	msTeams := helpers.InitializeTeams(slack, logger)
	jiraApiHelper := helpers.InitializeJIRA(slack, logger, msTeams)

	configData := GetConfigData()
	jiraSGRStats := jiraApiHelper.GetSGRJiraStatsForMessaging(configData.Teams)
	snykHelper := helpers.InitializeSnyk(slack, logger)

	/*------------SNYK - Get targets by Name ---------
	targets := []models.Target{}
	snykHelper.GetTargetIdsByName(configData.ReposOther, &targets)
	snykHelper.GetProjectIdsFromTargets(&targets)
	v := snykHelper.GetIssuesByOrgAndProject(targets)

	t := jiraApiHelper.CreateTickets(v, configData.Teams)

	fmt.Printf("############### JIRA CREATE Response ------ %+v\n", t)

	repoReport := getVulnerabilityListForRepoReport(configData.Teams, configData.ReposOther, v, "SNYK")
	repoReportSortedArr := models.SortRepoSummaryReportData(repoReport)

	for i, r := range repoReport {
		fmt.Printf("Index: %s, teamKey:%s, Repo: %s, C:%d, H:%d, M:%d, L:%d\n", i, r.TeamKey, r.RepoName, r.Critical, r.High, r.Medium, r.Low)
	}
	msTeams.SendMsTeamsMessages(configData.Teams, jiraSGRStats, repoReportSortedArr)
}

// func testGithub() {
// 	logger := helpers.InitializeLogger(true)
// 	slack := helpers.InitializeSlack(logger)
// 	configData := GetConfigData()
// 	gitHubHelper := helpers.InitializeGitHub(slack, logger)
// 	gitHubHelper.GetSCAandSastFindings(configData.Teams, configData.ReposGitHub)
// }

/// Workflow URLS

// ----------------------------security test

// - Working but expires on November 30th - "https://prod-37.westus.logic.azure.com:443/workflows/ceff4226c7094db18c5241a060950dd6/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=GSkvnKogrKezI5hXO2dfAT18JDQxGLywgpkJZCKoYgE"

// Replacement after Nov. 30th
//https://default415bb08f1a204fbe9b57313be70509.45.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/ceff4226c7094db18c5241a060950dd6/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=IECCfXSeqLiEgRZvQq21vTl-9NCG2R9VeOPoR5JcZAw

//TechBreeze
// Expires Nov 30th - https://prod-126.westus.logic.azure.com:443/workflows/707ed6503fb647f8a739b7edfba2b1ac/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=PR_roeSYTZhRXEHGHDu-IXAz1mnpiTO71YnpjknVC9g

//Replacement - https://default415bb08f1a204fbe9b57313be70509.45.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/707ed6503fb647f8a739b7edfba2b1ac/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=VJ1qmw3ZR0EhF9_t4ZBIPl6nEIGX7VLQ0Wq2M41aj1s */
