package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"threatlens/internal/detect"
	"threatlens/internal/models"
	"threatlens/internal/query"
	"threatlens/internal/report"
	"threatlens/internal/rules"
	"threatlens/internal/scanner"
	"threatlens/internal/store"
	storepkg "threatlens/internal/store"
	"threatlens/web"
	"time"
)

func runScan(querySet *models.QuerySet, ruleSet *models.RuleSet, db *storepkg.Store, srv *web.Server) []models.Detection {
	processQuery := query.GetQueryByName(querySet.Queries, "processes")
	if processQuery == nil {
		log.Println("'processes' query not found or not enabled")
		return nil
	}

	var processDetection []models.Process
	err := scanner.Run(processQuery.SQL, &processDetection)
	if err != nil {
		log.Println("Error running osquery:", err)
		return nil
	}

	dataItems := detect.ProcessesToMaps(processDetection)
	detections := detect.ApplyRules(ruleSet.Rules, "processes", dataItems)

	if err := db.SaveDetections(detections); err != nil {
		log.Println("Error saving detections:", err)
	}
	for _, d := range detections {
		borderColor := "border-yellow-500"
		textColor := "text-yellow-400"
		if d.Severity >= 50 {
			borderColor = "border-red-500"
			textColor = "text-red-400"
		} else if d.Severity < 30 {
			borderColor = "border-blue-500"
			textColor = "text-blue-400"
		}
		srv.Send(fmt.Sprintf(`
			<div class="event-item p-3 rounded-lg bg-slate-800/50 border-l-2 %s">
				<div class="flex justify-between items-start mb-1">
					<span class="text-xs font-semibold %s uppercase">%s</span>
					<span class="text-xs text-slate-500">%s</span>
				</div>
				<p class="text-sm text-slate-300">%s</p>
			</div>
		`, borderColor, textColor, d.Title, d.Timestamp, d.Evidence))
	}
	return detections
}

func main() {
	db, err := store.New("internal/db/threatlens.db")
	if err != nil {
		log.Fatalf("Error opening db: %v", err)
	}
	defer db.Close()

	report.PrintBanner()
	err = scanner.CheckOsqueryInstalled()
	if err != nil {
		log.Fatalf("Error in checking os query: %v", err)
	}
	querySet, err := query.LoadQueries("queries.json")
	if err != nil {
		log.Fatalf("Error in loading queries: %v", err)
	}
	ruleSet, err := rules.LoadRules("detection_rules.json")
	if err != nil {
		log.Fatalf("Error in loading rules: %v", err)
	}

	srv := web.New(db)
	go srv.Start(":8000")

	fmt.Println("Running initial scan....")
	runScan(querySet, ruleSet, db, srv)

	// continous scanning
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			fmt.Println("\n[+] Running scheduled scan...")
			runScan(querySet, ruleSet, db, srv)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down...")
	os.Exit(0)
}
