package mocks

import (
	"test-jira/pkg/models"
)

func GetMockScanResponse() map[string]models.RepoSummaryForReport {
	var mockRepo1, mockRepo2 models.RepoSummaryForReport
	mockRepos := make(map[string]models.RepoSummaryForReport)

	mockRepo1 = models.RepoSummaryForReport{Portfolio: "Maxwell", AppInfo: "AppInfo", Notes: "Notes", RepoName: "DailyFeats-Member", Team: "Milksteak", Total: 20, Critical: 10, High: 12, Medium: 3, Low: 5}
	mockRepo2 = models.RepoSummaryForReport{Portfolio: "Maxwell", AppInfo: "AppInfo", Notes: "Notes", RepoName: "DailyFeats-Neo", Team: "Xenon", Total: 25, Critical: 12, High: 4, Medium: 4, Low: 5}
	mockRepos["GH-maxwell-titan"] = mockRepo1
	mockRepos["GH-flax"] = mockRepo2
	return mockRepos
}

func GetMockConfig() models.ConfigData {

	repos := models.ConfigData{}
	ghRepos := []models.IncludedRepo{}

	ghRepos = append(ghRepos, models.IncludedRepo{Org: "DailyFeats", Name: "flax", Owner: "Tabasco"}, models.IncludedRepo{Org: "slus-customer-experience", Name: "slus-broker-portal", Owner: "Porkchop"})
	ghRepos = append(ghRepos, models.IncludedRepo{Org: "DailyFeats", Name: "flax", Owner: "Tabasco"}, models.IncludedRepo{Org: "slus-customer-experience", Name: "slus-broker-portal", Owner: "Porkchop"})

	repos.ReposGitHub = ghRepos
	repos.RepoDictionary = make(map[string]bool)

	return repos
}
