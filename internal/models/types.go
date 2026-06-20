package models

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
	Title     string
	Severity  int
	Evidence  string
	MitreID   string
	Timestamp string
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
