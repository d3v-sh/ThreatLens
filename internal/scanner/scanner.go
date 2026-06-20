package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func CheckOsqueryInstalled() error {
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

func Run(query string, v interface{}) error {

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
