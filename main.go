package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
	ColorBold   = "\033[1m"
)

type Process struct {
	Pid string `json:"pid"`
	// Parent    int64  `json:"parent"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Cmdline string `json:"cmdline"`
	// Username  string `json:"username"`
	StartTime string `json:"start_time"`
}

type LOLBinProcess struct {
	Pid     int64  `json:"pid"`
	Name    string `json:"name"`
	Cmdline string `json:"cmdline"`
}

type StartupProgram struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Args   string `json:"args"`
	Source string `json:"source"`
}

type RegistryKey struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Data string `json:"data"`
}

type ScheduledTask struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Action  string `json:"action"`
	Enabled int    `json:"enabled"`
	State   string `json:"state"`
}

type Listening_ports struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	PID      string `json:"pid"`
	Path     string `json:"path"`
}

type DnsQueries struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Flags int    `json:"flags"`
}

type LocalUsers struct {
	Username string `json:"username"`
	Uid      int64  `json:"uid"`
	Type     string `json:"type"`
}

type FileEntry struct {
	Path     string `json:"path"`
	Filename string `json:"filename"`
	CTime    int64  `json:"ctime"`
	MTime    int64  `json:"mtime"`
}

type WindowsEvents struct { // for inspecting logins
	Datetime      string `json:"datetime"`
	Source        string `json:"source"`
	Provider_name string `json:"provider_name"`
	Data          string `json:"data"`
}

type Query struct {
	Name        string `json:"name"`
	SQL         string `json:"sql"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type QuerySet struct {
	Queries []Query `json:"queries"`
}

type Detection struct {
	Title    string
	Severity int
	Evidence string
	MitreID  string
}

type Baseline struct {
	Ports map[int]bool
}

type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}
type Rule struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	DataSource  string      `json:"data_source"`
	Description string      `json:"description"`
	Conditions  []Condition `json:"conditions"`
	Exclusions  []Condition `json:"exclusions"`
	Severity    int         `json:"severity"`
	Mitre       string      `json:"mitre"`
}
type RuleSet struct {
	Rules []Rule `json:"rules"`
}

func calculateRisk(detections []Detection) int {
	total := 0
	for _, d := range detections {
		total += d.Severity
	}
	return total
}

func verdict(score int) string {
	switch {
	case score >= 70:
		return "COMPROMISED"
	case score >= 40:
		return "SUSPICIOUS"
	default:
		return "CLEAN"
	}
}

func checkOsqueryInstalled() error {
	osqueryPath := `C:\Program Files\osquery\osqueryi.exe`

	if _, err := os.Stat(osqueryPath); os.IsNotExist(err) {
		return fmt.Errorf("osquery not found at: %s", osqueryPath)
	}

	cmd := exec.Command(osqueryPath, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("osquery found but failed to execute: %v\nOutput: %s", err, string(output))
	}

	return nil
}

func printBanner() {
	banner := ColorCyan + `
  _____ _                    _   _                    
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___ 
   | | | '_ \| '__/ _ \/ _' | __| |   / _ \ '_ \/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
   |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/
` + ColorReset + ColorYellow + `
                    Made by d1_d3m0n
` + ColorReset
	fmt.Println(banner)
}

func printOsqueryInstallInstructions() {
	fmt.Println("\n" + ColorRed + strings.Repeat("=", 60) + ColorReset)
	fmt.Println(ColorBold + ColorRed + "OSQUERY NOT INSTALLED" + ColorReset)
	fmt.Println(ColorRed + strings.Repeat("=", 60) + ColorReset)
	fmt.Println("\nThis security scanner requires osquery to be installed.")
	fmt.Println("\n" + ColorCyan + "Installation Instructions:" + ColorReset)
	fmt.Println("\n1. Download osquery from:")
	fmt.Println(ColorBlue + "   https://osquery.io/downloads/official" + ColorReset)
	fmt.Println("\n2. For Windows:")
	fmt.Println("   - Download the .msi installer")
	fmt.Println("   - Run the installer as Administrator")
	fmt.Println("   - Default installation path: C:\\Program Files\\osquery\\")
	fmt.Println("\n3. Verify installation:")
	fmt.Println("   Open PowerShell/CMD as Administrator and run:")
	fmt.Println(ColorYellow + "   \"C:\\Program Files\\osquery\\osqueryi.exe\" --version" + ColorReset)
	fmt.Println("\n4. After installation, run this scanner again")
	fmt.Println(ColorRed + strings.Repeat("=", 60) + ColorReset)
}

func runOsquery(query string, v interface{}) error {

	query = strings.TrimSpace(strings.ReplaceAll(query, "\n", " "))
	query = strings.Join(strings.Fields(query), " ")

	cmd := exec.Command(
		`C:\Program Files\osquery\osqueryi.exe`,
		"--json",
		query,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("osquery failed: %v\nOutput: %s", err, string(output))
	}

	outputStr := strings.TrimSpace(string(output))
	if len(outputStr) == 0 || outputStr == "[]" {
		return json.Unmarshal([]byte("[]"), v)
	}

	if jsonErr := json.Unmarshal([]byte(outputStr), v); jsonErr != nil {
		return fmt.Errorf("json unmarshal error: %v\n", jsonErr)
	}

	return nil
}

var defaultQueries = []Query{
	{
		Name: "processes",
		SQL: `
			SELECT pid, parent, name, path, cmdline, start_time
			FROM processes;
		`,
	},
	{
		Name: "listening_ports",
		SQL: `
			SELECT lp.port, lp.protocol, lp.address, p.pid, p.name, p.path
			FROM listening_ports lp
			JOIN processes p ON lp.pid = p.pid;
		`,
	},
}

func getQueryByName(queries []Query, name string) *Query {
	for _, q := range queries {
		if q.Name == name && q.Enabled {
			return &q
		}
	}
	return nil
}

func NormalizePath(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}

func normalizeCmdline(c string) string {
	return strings.ToLower(c)
}

func detectSuspiciousProcesses(processes []Process) []Detection {
	var detections []Detection

	for _, p := range processes {
		path := NormalizePath(p.Path)

		if strings.Contains(path, `\appdata\`) || strings.Contains(path, `\temp\`) {
			detections = append(detections, Detection{
				Title:    "Suspicious Process Location",
				Severity: 30,
				Evidence: fmt.Sprintf("Process %s (PID %s) running from %s", p.Name, p.Pid, p.Path),
				MitreID:  "T1059",
			})
		}
	}
	return detections
}

func loadRules(filename string) (*RuleSet, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file:%v", err)
	}

	var ruleSet RuleSet
	if err := json.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %v", err)
	}

	return &ruleSet, nil
}

func loadQueries(filename string) (*QuerySet, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read queries: %v", err)
	}
	var querySet QuerySet
	if err := json.Unmarshal(data, &querySet); err != nil {
		return nil, fmt.Errorf("failed to parse queries file: %v", err)
	}
	return &querySet, nil
}

func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func evaluateCondition(condition Condition, data map[string]string) bool {
	fieldValue := normalizeValue(data[condition.Field])
	condValue := normalizeValue(condition.Value)

	switch condition.Operator {
	case "contains":
		return strings.Contains(fieldValue, condValue)
	case "equals":
		return fieldValue == condValue
	case "not_equals":
		return fieldValue != condValue
	case "starts_with":
		return strings.HasPrefix(fieldValue, condValue)
	case "ends_with":
		return strings.HasSuffix(fieldValue, condValue)
	case "regex":
		return strings.Contains(fieldValue, condValue)
	default:
		return false
	}

}

func evaluateRule(rule Rule, dataItem map[string]string) bool {
	for _, condition := range rule.Conditions {
		if !evaluateCondition(condition, dataItem) {
			return false
		}
	}
	for _, exclusion := range rule.Exclusions {
		if evaluateCondition(exclusion, dataItem) {
			return false
		}
	}
	return true
}

func applyRules(rules []Rule, datasource string, dataItems []map[string]string) []Detection {
	var detections []Detection
	var applicableRules []Rule

	for _, rule := range rules {
		if rule.DataSource == datasource {
			applicableRules = append(applicableRules, rule)
		}
	}

	for _, dataItem := range dataItems {
		for _, rule := range applicableRules {
			if evaluateRule(rule, dataItem) {
				var evidenceParts []string
				if name, ok := dataItem["name"]; ok && name != "" {
					evidenceParts = append(evidenceParts, fmt.Sprintf("Process: %s", name))
				}
				if pid, ok := dataItem["pid"]; ok && pid != "" {
					evidenceParts = append(evidenceParts, fmt.Sprintf("PID: %s", pid))
				}
				if path, ok := dataItem["path"]; ok && path != "" {
					evidenceParts = append(evidenceParts, fmt.Sprintf("Path: %s", path))
				}
				if cmdline, ok := dataItem["cmdline"]; ok && cmdline != "" && len(cmdline) < 200 {
					evidenceParts = append(evidenceParts, fmt.Sprintf("Cmdline: %s", cmdline))
				}
				evidence := strings.Join(evidenceParts, " | ")

				detections = append(detections, Detection{
					Title:    rule.Title,
					Severity: rule.Severity,
					Evidence: evidence,
					MitreID:  rule.Mitre,
				})
			}
		}
	}

	return detections
}

func processesToMaps(processes []Process) []map[string]string {
	var result []map[string]string

	for _, p := range processes {
		result = append(result, map[string]string{
			"pid":        p.Pid,
			"name":       p.Name,
			"path":       p.Path,
			"cmdline":    p.Cmdline,
			"start_time": p.StartTime,
		})
	}
	return result
}

func detectEncodedPowerShell(processes []Process) []Detection {
	var detections []Detection

	for _, p := range processes {
		cmd := normalizeCmdline(p.Cmdline)

		if strings.Contains(cmd, "powershell") &&
			strings.Contains(cmd, "-encodedcommand") {

			detections = append(detections, Detection{
				Title:    "Encoded PowerShell Execution",
				Severity: 40,
				Evidence: p.Cmdline,
				MitreID:  "T1059.001",
			})
		}

	}

	return detections
}
func createDefaultRules(filename string) {
	defaultRules := RuleSet{
		Rules: []Rule{
			{
				ID:          "SUSP_PROC_001",
				Title:       "Suspicious Process Location",
				Description: "Process running from temporary or AppData directory",
				DataSource:  "processes",
				Conditions: []Condition{
					{
						Field:    "path",
						Operator: "contains",
						Value:    "\\appdata\\",
					},
				},
				Severity: 30,
				Mitre:    "T1059",
			},
			{
				ID:          "SUSP_PROC_002",
				Title:       "Process in Temp Directory",
				Description: "Process running from temp directory",
				DataSource:  "processes",
				Conditions: []Condition{
					{
						Field:    "path",
						Operator: "contains",
						Value:    "\\temp\\",
					},
				},
				Severity: 30,
				Mitre:    "T1059",
			},
			{
				ID:          "SUSP_PS_001",
				Title:       "Encoded PowerShell Execution",
				Description: "PowerShell with encoded command detected",
				DataSource:  "processes",
				Conditions: []Condition{
					{
						Field:    "cmdline",
						Operator: "contains",
						Value:    "powershell",
					},
					{
						Field:    "cmdline",
						Operator: "contains",
						Value:    "-encodedcommand",
					},
				},
				Severity: 40,
				Mitre:    "T1059.001",
			},
			{
				ID:          "SUSP_PS_002",
				Title:       "PowerShell Download Cradle",
				Description: "PowerShell downloading content from internet",
				DataSource:  "processes",
				Conditions: []Condition{
					{
						Field:    "cmdline",
						Operator: "contains",
						Value:    "powershell",
					},
					{
						Field:    "cmdline",
						Operator: "contains",
						Value:    "downloadstring",
					},
				},
				Severity: 50,
				Mitre:    "T1059.001",
			},
			{
				ID:          "SUSP_PS_003",
				Title:       "PowerShell Bypass Execution Policy",
				Description: "PowerShell bypassing execution policy",
				DataSource:  "processes",
				Conditions: []Condition{
					{
						Field:    "cmdline",
						Operator: "contains",
						Value:    "powershell",
					},
					{
						Field:    "cmdline",
						Operator: "contains",
						Value:    "-executionpolicy bypass",
					},
				},
				Severity: 35,
				Mitre:    "T1059.001",
			},
			{
				ID:          "SUSP_CMD_001",
				Title:       "Suspicious CMD Execution",
				Description: "CMD running from unusual location",
				DataSource:  "processes",
				Conditions: []Condition{
					{
						Field:    "name",
						Operator: "equals",
						Value:    "cmd.exe",
					},
					{
						Field:    "path",
						Operator: "contains",
						Value:    "\\appdata\\",
					},
				},
				Severity: 40,
				Mitre:    "T1059.003",
			},
		},
	}

	data, err := json.MarshalIndent(defaultRules, "", "  ")
	if err != nil {
		fmt.Println("Error creating default rules:", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println("Error writing default rules file:", err)
		return
	}

	fmt.Printf("Created default rules file: %s\n", filename)
	fmt.Println("You can now edit this file to add or modify detection rules.")
}

func createDefaultQueries(filename string) {
	defaultQuerySet := QuerySet{
		Queries: defaultQueries,
	}

	data, err := json.MarshalIndent(defaultQuerySet, "", "  ")
	if err != nil {
		fmt.Println("Error creating default queries:", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println("Error writing default queries file:", err)
		return
	}

	fmt.Printf("Created default queries file: %s\n", filename)
	fmt.Println("You can now edit this file to add or modify queries.")
}

func main() {
	printBanner()
	fmt.Println(ColorBlue + "========== Host Security Scanner ==========" + ColorReset)
	fmt.Printf("Initializing...\n")

	fmt.Println("Checking osquery installation...")
	if err := checkOsqueryInstalled(); err != nil {
		fmt.Printf(ColorRed+"Error: %v\n"+ColorReset, err)
		printOsqueryInstallInstructions()
		return
	}
	fmt.Printf(ColorGreen + "✓ Osquery is installed and working\n" + ColorReset)

	queriesFile := "queries.json"
	querySet, err := loadQueries(queriesFile)
	if err != nil {
		fmt.Printf("Error loading queries from %s: %v\n", queriesFile, err)
		fmt.Println("Creating default queries file...")
		createDefaultQueries(queriesFile)
		return
	}

	rulesFile := "detection_rules.json"
	ruleSet, err := loadRules(rulesFile)
	if err != nil {
		fmt.Printf("Error loading rules from %s: %v\n", rulesFile, err)
		fmt.Println("Creating a default rules file...")
		createDefaultRules(rulesFile)
		return
	}
	fmt.Printf(ColorGreen+"✓ Loaded %d queries\n"+ColorReset, len(ruleSet.Rules))
	fmt.Printf(ColorGreen+"✓ Loaded %d queries\n"+ColorReset, len(querySet.Queries))

	processQuery := getQueryByName(querySet.Queries, "processes")
	if processQuery == nil {
		fmt.Println("Error: 'processes' query not found or disbaled")
		return
	}

	var detections []Detection

	fmt.Println("Fetching process information...")
	var processes []Process

	err = runOsquery(processQuery.SQL, &processes)
	if err != nil {
		fmt.Println(ColorRed+"Error Fetching processes:"+ColorReset, err)
		return
	}
	fmt.Printf(ColorGreen+"✓ Found %d processes\n"+ColorReset, len(processes))

	processData := processesToMaps(processes)
	detections = append(detections, applyRules(ruleSet.Rules, "processes", processData)...)

	portsQuery := getQueryByName(querySet.Queries, "listening_ports")
	if portsQuery == nil {
		fmt.Println(ColorYellow + "Warning: 'listening_ports' query not found or disabled, skipping..." + ColorReset)
	} else {
		fmt.Println("Fetching listening ports...")
		var ports []Listening_ports
		err = runOsquery(portsQuery.SQL, &ports)
		if err != nil {
			fmt.Println(ColorRed+"Error fetching listening ports:"+ColorReset, err)
		} else {
			fmt.Printf(ColorGreen+"✓ Found %d listening ports\n"+ColorReset, len(ports))
		}
	}

	score := calculateRisk(detections)
	status := verdict(score)

	fmt.Println("\n========== Host Security Assessment ==========")
	fmt.Println("Status:", status)
	fmt.Println("Risk Score:", score)
	fmt.Println("Detections:")

	if len(detections) == 0 {
		fmt.Println(ColorGreen + "  ✓ No suspicious activity detected." + ColorReset)
	} else {
		for i, d := range detections {
			severityColor := ColorYellow
			if d.Severity >= 50 {
				severityColor = ColorRed
			} else if d.Severity < 30 {
				severityColor = ColorGreen
			}

			fmt.Printf("\n"+ColorBold+"%d. [%s] %s\n"+ColorReset, i+1, d.MitreID, d.Title)
			fmt.Printf("   Severity: "+severityColor+"%d"+ColorReset+"\n", d.Severity)
			fmt.Printf("   Evidence: %s\n", d.Evidence)
		}
	}

	fmt.Println("\n" + ColorBlue + strings.Repeat("=", 50) + ColorReset)

}
