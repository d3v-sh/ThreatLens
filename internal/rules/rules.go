package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"threatlens/internal/models"
	"time"
)

func LoadRules(filename string) (*models.RuleSet, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file:%v", err)
	}

	var ruleSet models.RuleSet
	if err := json.Unmarshal(data, &ruleSet); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %v", err)
	}

	return &ruleSet, nil
}

func ApplyRules(rules []models.Rule, datasource string, dataItems []map[string]string) []models.Detection {
	var detections []models.Detection
	var applicableRules []models.Rule

	for _, rule := range rules {
		if rule.DataSource == datasource {
			applicableRules = append(applicableRules, rule)
		}
	}

	for _, dataItem := range dataItems {
		for _, rule := range applicableRules {
			if EvaluateRule(rule, dataItem) {
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
					Title:     rule.Title,
					Severity:  rule.Severity,
					Evidence:  evidence,
					MitreID:   rule.Mitre,
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				})
			}
		}
	}

	return detections
}

func EvaluateRule(rule models.Rule, dataItem map[string]string) bool {
	for _, condition := range rule.Conditions {
		if evaluateCondition(condition, dataItem) {
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

func evaluateCondition(condition models.Condition, data map[string]string) bool {
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

func normalizeValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
