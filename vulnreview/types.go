package vulnreview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const MaxPackages = 500
const MaxBody = 2 << 20
const Coverage = "cve.now indexed vulnerabilities only. No indexed match is not a guarantee of safety. Inventory evidence does not establish deployment or exploitability."
const Attribution = "Source: cve.now, built and run by Sazabi — https://sazabi.com/"

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}
type Inventory struct {
	Packages []Package `json:"packages"`
	Source   string    `json:"source"`
	Skipped  int       `json:"skipped"`
	Warnings []string  `json:"warnings"`
}
type Project struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Inventory      Inventory `json:"inventory"`
	InventoryHash  string    `json:"inventory_hash"`
	Daily          bool      `json:"daily"`
	ApprovedAt     time.Time `json:"approved_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	AcknowledgedAt time.Time `json:"acknowledged_at"`
}
type Finding struct {
	Key            string    `json:"key"`
	ID             string    `json:"id"`
	Aliases        []string  `json:"aliases"`
	Package        Package   `json:"package"`
	Title          string    `json:"title"`
	Applicability  string    `json:"applicability"`
	Evidence       string    `json:"evidence"`
	CVSS           *float64  `json:"cvss"`
	KnownExploited bool      `json:"known_exploited"`
	FixedVersions  []string  `json:"fixed_versions"`
	References     []string  `json:"references"`
	URL            string    `json:"url"`
	RetrievedAt    time.Time `json:"retrieved_at"`
}
type Changes struct {
	New              int `json:"new"`
	Changed          int `json:"changed"`
	NoLongerObserved int `json:"no_longer_observed"`
}
type Run struct {
	ID            string     `json:"id"`
	ProjectID     string     `json:"project_id"`
	InventoryHash string     `json:"inventory_hash"`
	Inventory     Inventory  `json:"inventory"`
	Status        string     `json:"status"`
	Findings      []Finding  `json:"findings"`
	Warnings      []string   `json:"warnings"`
	Checked       int        `json:"checked"`
	Error         string     `json:"error"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	Changes       Changes    `json:"changes"`
	Coverage      string     `json:"coverage"`
	Attribution   string     `json:"attribution"`
	Decisions     []Decision `json:"decisions"`
}
type RunSummary struct {
	ID            string     `json:"id"`
	Status        string     `json:"status"`
	InventoryHash string     `json:"inventory_hash"`
	CreatedAt     time.Time  `json:"created_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	Findings      int        `json:"findings"`
	Changes       Changes    `json:"changes"`
	Error         string     `json:"error"`
}
type Decision struct {
	ID             string    `json:"id"`
	ProjectID      string    `json:"project_id"`
	FindingKey     string    `json:"finding_key"`
	PackageVersion string    `json:"package_version"`
	InventoryHash  string    `json:"inventory_hash"`
	Status         string    `json:"status"`
	Reason         string    `json:"reason"`
	CreatedAt      time.Time `json:"created_at"`
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func findingKey(p Package, id string) string {
	return digest([]string{p.Ecosystem, p.Name, p.Version, id})
}
func normalizeRun(r *Run) {
	legacy := false
	for i := range r.Findings {
		f := &r.Findings[i]
		key := findingKey(f.Package, f.ID)
		if f.Key != key {
			f.Key = key
			legacy = true
		}
	}
	if legacy {
		r.Warnings = append(r.Warnings, "Legacy finding identities were upgraded to include package version. Legacy decisions without version evidence are retained in the audit log and are not automatically reapplied.")
	}
}
