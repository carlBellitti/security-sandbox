package helpers

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"test-jira/pkg/config"
	"test-jira/pkg/models"

	goteamsnotify "github.com/atc0005/go-teams-notify/v2"
	"github.com/atc0005/go-teams-notify/v2/adaptivecard"
)

const SECURITY_TEST_WEBHOOK_URL = "https://prod-37.westus.logic.azure.com:443/workflows/ceff4226c7094db18c5241a060950dd6/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=GSkvnKogrKezI5hXO2dfAT18JDQxGLywgpkJZCKoYgE"

const SECURITY_TEST_FOR_NOV_30 = "https://default415bb08f1a204fbe9b57313be70509.45.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/ceff4226c7094db18c5241a060950dd6/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=IECCfXSeqLiEgRZvQq21vTl-9NCG2R9VeOPoR5JcZAw"

type MsTeams struct {
	AppConfig *config.AppConfig
	MstClient *goteamsnotify.TeamsClient
}

func InitializeTeams(a *config.AppConfig) *MsTeams {
	mstClient := goteamsnotify.NewTeamsClient()
	return &MsTeams{AppConfig: a, MstClient: mstClient}
}

func (T *MsTeams) SendMsTeamsMessages(teamData map[string]models.Team, jiraStatsSGR map[string]JiraStats, repoReport []models.RepoSummaryForReport) {
	for team := range teamData {
		if !teamData[team].TeamsEnabled {
			T.AppConfig.Logger.Log("Teams not enabled for " + team)
			continue
		}
		//webhookUrl := teamData[team].TeamsWebHookURL
		webhookUrl := SECURITY_TEST_WEBHOOK_URL
		T.SendMsTeamsSGRMessages(team, webhookUrl, jiraStatsSGR)
		msTeamsRepoData := convertReportData(repoReport)
		T.SendMsTeamsSnykMessages(team, webhookUrl, msTeamsRepoData[team])
	}
}

func (T *MsTeams) SendMsTeamsSnykMessages(team string, webhookUrl string, snykData []slackRepoData) {

	rows := getTableRowsFromSnykStats(snykData)
	tableRows := []adaptivecard.TableRow{}
	headerRow := adaptivecard.TableRow{

		Type: adaptivecard.TypeTableRow,
		Cells: []adaptivecard.TableCell{
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Repo",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Critical",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "High",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Medium",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Low",
					},
				},
			},
		},
	}
	tableRows = append(tableRows, headerRow)
	tableRows = append(tableRows, rows...)

	card := adaptivecard.Card{
		Type:    adaptivecard.TypeAdaptiveCard,
		Schema:  adaptivecard.AdaptiveCardSchema,
		Version: fmt.Sprintf(adaptivecard.AdaptiveCardVersionTmpl, adaptivecard.AdaptiveCardMaxVersion),
		Body: []adaptivecard.Element{
			{
				Type:  adaptivecard.TypeElementTextBlock,
				Text:  "**SCA Items** - " + team + "\n[JIRA Link](https://sunlife.atlassian.net/jira/software/c/projects/SAUG/boards/9207?quickFilter=48541)",
				Style: adaptivecard.TextBlockStyleHeading,
			},
			{
				Type:              adaptivecard.TypeElementTable,
				GridStyle:         adaptivecard.ContainerStyleAccent,
				ShowGridLines:     func() *bool { show := true; return &show }(),
				FirstRowAsHeaders: func() *bool { show := true; return &show }(),

				Columns: []adaptivecard.Column{
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          4,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentBottom,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentCenter,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentCenter,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentBottom,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentBottom,
					},
				},
				Rows: tableRows,
			},
		},
	}
	card.SetFullWidth()

	msg := &adaptivecard.Message{
		Type: adaptivecard.TypeMessage,
	}

	msg.Attach(card)

	if err := msg.Prepare(); err != nil {
		log.Printf(
			"failed to prepare message payload: %v",
			err,
		)
		os.Exit(1)
	}
	//fmt.Println(msg.PrettyPrint())

	// Send the message with default timeout/retry settings.
	if err := T.MstClient.Send(webhookUrl, msg); err != nil {
		log.Printf(
			"failed to send message: %v",
			err,
		)
		os.
			Exit(1)
	}

}

func getTableRowsFromSnykStats(stats []slackRepoData) []adaptivecard.TableRow {
	rows := []adaptivecard.TableRow{}

	for _, s := range stats {

		row := adaptivecard.TableRow{
			Type: adaptivecard.TypeTableRow,
			Cells: []adaptivecard.TableCell{
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: s.RepoName,
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: strconv.Itoa(s.Critical),
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: strconv.Itoa(s.High),
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: strconv.Itoa(s.Medium),
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: strconv.Itoa(s.Low),
						},
					},
				},
			},
		}
		rows = append(rows, row)
	}

	return rows
}

func (T *MsTeams) SendMsTeamsSGRMessages(team string, webhookUrl string, jiraStatsSGR map[string]JiraStats) {

	tableRows := []adaptivecard.TableRow{}
	headerRow := adaptivecard.TableRow{

		Type: adaptivecard.TypeTableRow,
		Cells: []adaptivecard.TableCell{
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Jira Link",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Application",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Severity",
					},
				},
			},
			{
				Type: adaptivecard.TypeTableCell,
				Items: []*adaptivecard.Element{
					{
						Type: adaptivecard.TypeElementTextBlock,
						Wrap: true,
						Text: "Due Date",
					},
				},
			},
		},
	}
	tableRows = append(tableRows, headerRow)
	tableRows = append(tableRows, getTableRowsFromSGRStats(jiraStatsSGR[team])...)

	card := adaptivecard.Card{
		Type:    adaptivecard.TypeAdaptiveCard,
		Schema:  adaptivecard.AdaptiveCardSchema,
		Version: fmt.Sprintf(adaptivecard.AdaptiveCardVersionTmpl, adaptivecard.AdaptiveCardMaxVersion),
		Body: []adaptivecard.Element{
			{
				Type:  adaptivecard.TypeElementTextBlock,
				Text:  "**Security Gap Items (PEN tests etc.)** - " + team,
				Style: adaptivecard.TextBlockStyleHeading,
			},
			{
				Type:              adaptivecard.TypeElementTable,
				GridStyle:         adaptivecard.ContainerStyleAccent,
				ShowGridLines:     func() *bool { show := true; return &show }(),
				FirstRowAsHeaders: func() *bool { show := true; return &show }(),

				Columns: []adaptivecard.Column{
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentBottom,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          2,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentCenter,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentCenter,
					},
					{
						Type:                           adaptivecard.TypeTableColumnDefinition,
						Width:                          1,
						HorizontalCellContentAlignment: adaptivecard.HorizontalAlignmentLeft,
						VerticalCellContentAlignment:   adaptivecard.VerticalAlignmentBottom,
					},
				},
				Rows: tableRows,
			},
		},
	}
	card.SetFullWidth()

	msg := &adaptivecard.Message{
		Type: adaptivecard.TypeMessage,
	}

	msg.Attach(card)

	if err := msg.Prepare(); err != nil {
		log.Printf(
			"failed to prepare message payload: %v",
			err,
		)
		os.Exit(1)
	}
	//fmt.Println(msg.PrettyPrint())

	// Send the message with default timeout/retry settings.
	if err := T.MstClient.Send(webhookUrl, msg); err != nil {
		log.Printf(
			"failed to send message: %v",
			err,
		)
		os.
			Exit(1)
	}

}

func getTableRowsFromSGRStats(stats JiraStats) []adaptivecard.TableRow {
	rows := []adaptivecard.TableRow{}
	allIssues := stats.PastDue
	allIssues = append(allIssues, stats.DueInFuture...)
	for _, i := range allIssues {

		row := adaptivecard.TableRow{
			Type: adaptivecard.TypeTableRow,
			Cells: []adaptivecard.TableCell{
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: "[" + i.Key + "](https://sunlife.atlassian.net/browse/" + i.Key + ")",
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: i.Fields.ApplicationName,
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: i.Fields.Priority.Name,
						},
					},
				},
				{
					Type: adaptivecard.TypeTableCell,
					Items: []*adaptivecard.Element{
						{
							Type: adaptivecard.TypeElementTextBlock,
							Wrap: false,
							Text: i.Fields.RequestDueDate,
						},
					},
				},
			},
		}
		rows = append(rows, row)
	}

	return rows
}

/******* THese are not used

func (T *MsTeams) PostMessageToChannel() {

	// Set webhook url. - test chat
	webhookUrl := "https://default415bb08f1a204fbe9b57313be70509.45.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/ceff4226c7094db18c5241a060950dd6/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=IECCfXSeqLiEgRZvQq21vTl-9NCG2R9VeOPoR5JcZAw"

	// The title for message (first TextBlock element).
	msgTitle := "Hello world"

	// Formatted message body.
	msgText := "Here are some examples of formatted stuff like " +
		"\n * this list itself  \n * **bold** \n * *italic* \n * ***bolditalic***"

	// Create message using provided formatted title and text.
	msg, err := adaptivecard.NewSimpleMessage(msgText, msgTitle, true)
	if err != nil {
		log.Printf(
			"failed to create message: %v",
			err,
		)
		os.Exit(1)
	}

	// Send the message with default timeout/retry settings.
	if err := T.MstClient.Send(webhookUrl, msg); err != nil {
		log.Printf(
			"failed to send message: %v",
			err,
		)
		os.Exit(1)
	}

}

func (T *MsTeams) PostTableToChannel() {

	// Initialize a new Microsoft Teams client.
	mstClient := goteamsnotify.NewTeamsClient()

	// Set webhook url - Carl/Ethan
	//webhookUrl := "https://prod-41.westus.logic.azure.com:443/workflows/2bc984d61bc74f2991ef21c404cbf7ae/triggers/manual/paths/invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=UpenguqIcdaIlRVScg-e1O_gEaf4bfA8Z_G3Hcz_5jM"

	// carl-test
	webhookUrl := "https://default415bb08f1a204fbe9b57313be70509.45.environment.api.powerplatform.com:443/powerautomate/automations/direct/workflows/ceff4226c7094db18c5241a060950dd6/triggers/manual/paths/invoke?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=IECCfXSeqLiEgRZvQq21vTl-9NCG2R9VeOPoR5JcZAw"

	vals := [][]string{
		{"column1", "column2", "column3"},
		{
			"row 1, value 1",
			"row 1, value 2",
			"row 1, value 3",
		},
		{
			"",
			"",
			"",
		},
		{
			"row 3, value 1",
			"row 3, value 2",
			"row 3, value 3",
		},
	}

	cellsCollection := make([][]adaptivecard.TableCell, 0, len(vals))

	for _, row := range vals {
		items := make([]interface{}, len(row))
		for i := range row {
			items[i] = row[i]
		}

		tableCells, err := adaptivecard.NewTableCellsWithTextBlock(items)
		if err != nil {
			log.Printf(
				"failed to create table cells: %v",
				err,
			)
			os.Exit(1)
		}

		cellsCollection = append(cellsCollection, tableCells)
	}

	table, err := adaptivecard.NewTableFromTableCells(cellsCollection, 0, true, true)
	if err != nil {
		log.Printf(
			"failed to create table: %v",
			err,
		)
		os.Exit(1)
	}

	card := adaptivecard.NewCard()

	title := adaptivecard.NewTitleTextBlock("Test", true)

	card.Body = append(card.Body, title, table)

	msg := &adaptivecard.Message{
		Type: adaptivecard.TypeMessage,
	}

	msg.Attach(card)

	if err := msg.Prepare(); err != nil {
		log.Printf(
			"failed to prepare message payload: %v",
			err,
		)
		os.Exit(1)
	}
	fmt.Println(msg.PrettyPrint())

	// Send the message with default timeout/retry settings.
	if err := mstClient.Send(webhookUrl, msg); err != nil {
		log.Printf(
			"failed to send message: %v",
			err,
		)
		os.Exit(1)
	}

}

func getCellValuesFromStats(stats JiraStats) [][]string {
	allIssues := stats.PastDue
	allIssues = append(allIssues, stats.DueInFuture...)

	vals := [][]string{}
	rowData := []string{}
	rowData = append(rowData, "Link", "Severity", "Due Date")
	vals = append(vals, rowData)

	for _, i := range allIssues {
		rowData = []string{"https://sunlife.atlassian.net/browse/" + i.Key, i.Fields.Priority.Name, i.Fields.RequestDueDate}
		vals = append(vals, rowData)
	}

	return vals
}

*/
