# Security Metrics Action

A Go application that aggregates security vulnerabilities from GitHub repositories, manages JIRA tickets for vulnerability tracking, and provides automated reporting and notifications via Slack and Google Drive.

## Overview

This application performs daily scans to:
- Collect SCA (Software Composition Analysis) and SAST (Static Application Security Testing) vulnerabilities from GitHub
- Create and manage JIRA tickets for tracking vulnerability remediation
- Export vulnerability data to Google Drive in CSV format
- Send automated Slack notifications to development teams with vulnerability statistics and JIRA ticket status

## Architecture

### Core Components

- **GitHub Integration**: Fetches vulnerability data using GraphQL API (Dependabot alerts) and REST API (Code Scanning alerts)
- **JIRA Integration**: Automatically creates, updates, and transitions tickets based on vulnerability status
- **Google Drive**: Stores CSV reports for current vulnerabilities, resolved vulnerabilities, and repository summaries
- **Slack**: Sends scheduled notifications to team channels with vulnerability metrics and JIRA statistics

### Key Workflows

1. Scan GitHub repositories for SCA and SAST findings
2. Categorize vulnerabilities by severity, status (open/fixed/dismissed), and scope (production/development)
3. Create JIRA tickets for new production vulnerabilities
4. Update JIRA tickets when patches become available
5. Auto-transition tickets to "Done" when vulnerabilities are fixed or dismissed
6. Generate CSV reports and upload to Google Drive
7. Send Slack notifications with vulnerability and JIRA statistics

## Configuration

### Environment Variables

Required secrets (stored as GitHub secrets):
- `GIT_HUB_TOKEN`: GitHub personal access token with appropriate permissions
- `JIRA_TOKEN`: JIRA API authentication token
- `SLACK_TOKEN`: Slack bot API token

### Configuration Files

#### `config.json` (Production)
```json
{
  "teams": {
    "teamKey": {
      "displayName": "Team Name",
      "slackID": "CHANNEL_ID",
      "jiraTeamID": "TEAM_ID",
      "jiraEnabled": true,
      "slackEnabled": true
    }
  },
  "reposGithub": [
    {
      "org": "organization-name",
      "name": "repository-name",
      "owner": "teamKey",
      "portfolio": "Portfolio Name",
      "appInfo": "Application Info",
      "notes": "Additional notes"
    }
  ]
}
```

#### `config-dev.json`
Development configuration for testing (uses `-dev` Google Drive files and test Slack channels)

#### `credentials.json`
Google Drive service account credentials (not committed to repository)

## API Integrations

### GitHub API
- **GraphQL API** (`https://api.github.com/graphql`): Fetches Dependabot security alerts with pagination support
- **REST API** (`https://api.github.com/repos/{org}/{repo}/code-scanning/alerts`): Retrieves SAST findings from code scanning tools
- Supports repository filtering by organization and handles archived/disabled repositories

### JIRA API
- **Ticket Creation**: Creates tickets in the SAUG project for production vulnerabilities
- **Ticket Updates**: Updates ticket summaries and descriptions when patches become available
- **Status Transitions**: Automatically moves tickets through workflow states (To Do → In Progress → In Testing → Ready to Deploy → Done)
- **Statistics**: Retrieves past due and upcoming due tickets for Slack reporting
- Custom fields: `customfield_24137` (Team), `customfield_24140` (Requested Due Date), `customfield_24141` (Vulnerability ID)

### Google Drive API
Manages six CSV files (3 production + 3 development):
- **Current vulnerabilities**: Open security findings with severity, patch status, and age
- **Resolved vulnerabilities**: Fixed or dismissed findings with resolution dates
- **Repository report**: High-level summary by repository with vulnerability counts by severity

### Slack API
- Sends automated messages to team channels (Monday and Thursday by default)
- Includes GitHub vulnerability statistics and JIRA ticket status
- Supports forced notifications via command-line flag

## Data Models

### Vulnerability Structure
```go
type Vulnerability struct {
    CreatedAt        string
    ResolvedAt       string
    FixedOrDismissed string
    HasPatch         string
    Repo             string
    Package          string
    GHSAorID         string
    CVE              string
    Severity         string
    DaysSince        string
    Source           string
    URL              string
    CurrentStatus    string
    Team             string
    Org              string
    RequestedDueDate string
}
```

### Severity Levels & SLAs
- **CRITICAL**: 14 days
- **HIGH**: 30 days
- **MEDIUM/MODERATE**: 180 days
- **LOW**: 360 days

## Execution Flow

1. **Initialize APIs**: Set up connections to GitHub, JIRA, Slack, and Google Drive
2. **Load Configuration**: Read team data and repository list from `config.json`
3. **Fetch GitHub Data**: 
   - Get SCA findings (Dependabot alerts) for all configured repositories
   - Get SAST findings (code scanning alerts) for all configured repositories
   - Categorize by status (open/fixed/dismissed) and scope (production/development)
4. **Generate Reports**: Create sorted vulnerability lists and repository summaries
5. **Update Google Drive**: Upload current, resolved, and report CSV files
6. **Manage JIRA Tickets**:
   - Update blocked tickets that now have patches available
   - Move tickets from Blocked to To Do when patches are available
   - Create new tickets for open vulnerabilities
   - Move new tickets without patches to Blocked status
   - Auto-transition fixed/dismissed tickets to Done
7. **Gather JIRA Statistics**: Retrieve SAUG and SGR ticket metrics
8. **Send Slack Notifications**: Post vulnerability and JIRA statistics to team channels

## Command-Line Options

For local development and testing:

```bash
go run cmd/main.go [options]
```

**Available Options:**
- `noGH`: Skip GitHub vulnerability retrieval
- `dev`: Use development configuration and output files
- `mockData`: Use mock vulnerability data instead of real API calls
- `mockRepos`: Use mock repository list
- `debug`: Enable additional debugging code
- `slack`: Force Slack messages (ignore day-of-week check)

## Links

- **JIRA Board**: [https://sunlife.atlassian.net/jira/software/c/projects/SAUG/boards/9207](https://sunlife.atlassian.net/jira/software/c/projects/SAUG/boards/9207)
- **Google Sheet**: [Security Vulnerabilities Dashboard](https://docs.google.com/spreadsheets/d/1Ke8xaDqlyqJp-8HiOEyCNW3TwRtJnQHpjoNSkY7KTNU/edit?usp=sharing)

## File Structure

```
security-metrics-action/
├── cmd/
│   └── main.go              # Application entry point
├── internal/
│   ├── helpers/
│   │   ├── github.go        # GitHub API client
│   │   ├── google.go        # Google Drive client
│   │   ├── jira.go          # JIRA API client
│   │   ├── logger.go        # Logging utilities
│   │   ├── scan.go          # Main scan orchestration
│   │   └── slack.go         # Slack API client
│   ├── models/
│   │   └── model.go         # Data structures
│   └── mocks/
│       └── mocks.go         # Mock data for testing
├── config.json              # Production configuration
├── config-dev.json          # Development configuration
├── credentials.json         # Google service account (not committed)
├── go.mod                   # Go dependencies
└── README.md                # This file
```

## Dependencies

- `github.com/slack-go/slack` - Slack API client
- `google.golang.org/api` - Google Drive API client

## Development Notes

### Adding a New Repository
1. Add repository entry to `reposGithub` array in `config.json`
2. Ensure the team key exists in the `teams` configuration
3. Repository will be included in the next scan

### Adding a New Team
1. Add team entry to `teams` object in `config.json`
2. Set appropriate Slack channel ID and JIRA team ID
3. Configure `jiraEnabled` and `slackEnabled` flags

### JIRA Ticket Lifecycle
- **Created**: New production vulnerability detected
- **Blocked**: No patch available (includes "(NO FIX AVAILABLE)" suffix)
- **To Do**: Patch becomes available (moved from Blocked)
- **Done**: Vulnerability fixed or dismissed in GitHub

### Vulnerability Key Format
```
{Source}-{Repo}-{Package}-{GHSA/ID}-{CVE}-{CreatedDate}
```

Example: `Dependabot-slus-broker-portal-axios-GHSA-1234-abcd-5678-CVE-2024-1234-2024-01-15`

## GitHub API Details

### SCA Findings (Dependabot)
The application uses GitHub's GraphQL API to retrieve Dependabot security alerts:

- **Endpoint**: `https://api.github.com/graphql`
- **Authentication**: OAuth token via Basic Auth
- **Pagination**: Supports cursor-based pagination (50 alerts per page)
- **Data Retrieved**:
  - Alert creation/dismissal/fix timestamps
  - Dependency scope (PRODUCTION vs DEVELOPMENT)
  - Vulnerability severity (CRITICAL, HIGH, MODERATE, LOW)
  - Package information (name, ecosystem)
  - Security advisory details (GHSA ID, CVE, permalink)
  - Patch availability and version

### SAST Findings (Code Scanning)
The application uses GitHub's REST API to retrieve code scanning alerts:

- **Endpoint**: `https://api.github.com/repos/{org}/{repo}/code-scanning/alerts`
- **Authentication**: Bearer token
- **API Version**: `2022-11-28`
- **Data Retrieved**:
  - Alert number and state (open, fixed, dismissed)
  - Creation/update/fix/dismissal timestamps
  - Rule information (severity, description, tags)
  - Tool information (name, version)
  - Code location (file path, line numbers)
  - Security severity level

### Repository Filtering
- Automatically skips archived and disabled repositories
- Logs warnings for archived/disabled repositories
- Handles pagination for repositories with many alerts
- Supports both organization and repository-level queries

## Troubleshooting

### Common Issues

**Go module error with `cloud.google.com/go`**:
The `exclude` directive in `go.mod` prevents conflicts between the monolithic v0.34.0 and newer submodules. If you encounter ambiguous import errors, ensure `exclude cloud.google.com/go v0.34.0` is present.

**JIRA ticket creation failures**:
Verify the JIRA team IDs in `config.json` match the actual team IDs in JIRA's `customfield_24137`.

**Google Drive upload failures**:
Ensure the service account has write permissions to the target folder and the `credentials.json` file is valid.

**Slack messages not sending**:
Check that `slackEnabled` is `true` for the team and it's Monday or Thursday (or use the `slack` command-line flag to override).

**GitHub API rate limiting**:
The application uses pagination to handle large result sets. If rate limiting occurs, consider:
- Reducing scan frequency
- Splitting repositories across multiple runs
- Using a GitHub App with higher rate limits

**Development vs Production scope**:
Dependencies with `dependencyScope: "DEVELOPMENT"` are prefixed with `DEV-` in their severity level and tracked separately from production vulnerabilities.

## License

Internal Sun Life Financial tool - not for public distribution.



