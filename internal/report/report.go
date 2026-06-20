package report

import (
	"fmt"
	"strings"
	"threatlens/internal/models"
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

func PrintBanner() {
	banner := ColorCyan + `
  _____ _                    _   _                    
 |_   _| |__  _ __ ___  __ _| |_| |    ___ _ __  ___ 
   | | | '_ \| '__/ _ \/ _' | __| |   / _ \ '_ \/ __|
   | | | | | | | |  __/ (_| | |_| |__|  __/ | | \__ \
   |_| |_| |_|_|  \___|\__,_|\__|_____\___|_| |_|___/
` + ColorReset + ColorYellow + `
                    Made by d3v_sH
` + ColorReset
	fmt.Println(banner)
}

func Print(detections []models.Detection, score int, status string) {
	fmt.Println("\n========== Host Security Assessment ==========")
	fmt.Println("Status:", status)
	fmt.Println("Risk Score:", score)
	fmt.Println("Detections:")

	if len(detections) == 0 {
		fmt.Println(ColorGreen + "  ✓ No suspicious activity detected." + ColorReset)
		return
	}

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

	fmt.Println("\n" + ColorBlue + strings.Repeat("=", 50) + ColorReset)
}
