package detect

import (
	"fmt"
	"threatlens/internal/models"
	"threatlens/internal/rules"
	"strings"
)

func normalizePath(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}

func normalizeCmdline(c string) string {
	return strings.ToLower(c)
}

func detectSuspiciousProcesses(processes []models.Process) []models.Detection {
	var detections []models.Detection

	for _, p := range processes {
		path := normalizePath(p.Path)

		if strings.Contains(path, `\appdata\`) || strings.Contains(path, `\temp\`) {
			detections = append(detections, models.Detection{
				Title:    "Suspicious Process Location",
				Severity: 30,
				Evidence: fmt.Sprintf("Process %s (PID %s) running from %s", p.Name, p.Pid, p.Path),
				MitreID:  "T1059",
			})
		}
	}
	return detections
}

func detectEncodedPowerShell(processes []models.Process) []models.Detection {
	var detections []models.Detection

	for _, p := range processes {
		cmd := normalizeCmdline(p.Cmdline)

		if strings.Contains(cmd, "powershell") &&
			strings.Contains(cmd, "-encodedcommand") {

			detections = append(detections, models.Detection{
				Title:    "Encoded PowerShell Execution",
				Severity: 40,
				Evidence: p.Cmdline,
				MitreID:  "T1059.001",
			})
		}

	}

	return detections
}

func CalculateRisk(detections []models.Detection) int {
	total := 0
	for _, d := range detections {
		total += d.Severity
	}
	return total
}

func Verdict(score int) string {
	switch {
	case score >= 70:
		return "COMPROMISED"
	case score >= 40:
		return "SUSPICIOUS"
	default:
		return "CLEAN"
	}
}

func ApplyRules(ruleList []models.Rule, datasource string, dataItems []map[string]string) []models.Detection {
	var detections []models.Detection
	var applicableRules []models.Rule

	for _, rule := range ruleList {
		if rule.DataSource == datasource {
			applicableRules = append(applicableRules, rule)
		}
	}

	for _, dataItem := range dataItems {
		for _, rule := range applicableRules {
			if rules.EvaluateRule(rule, dataItem) {
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

				detections = append(detections, models.Detection{
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

func ProcessesToMaps(processes []models.Process) []map[string]string {
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
