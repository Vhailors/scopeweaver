package vulnreview

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

var exactVersion = regexp.MustCompile(`^[vV]?[0-9][0-9A-Za-z.+_:-]{0,199}$`)
var packageName = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@/._:+-]{0,199}$`)
var ecosystems = map[string]string{"npm": "npm", "pypi": "PyPI", "go": "Go", "crates.io": "crates.io", "rubygems": "RubyGems", "maven": "Maven", "nuget": "NuGet", "packagist": "Packagist", "hex": "Hex", "pub": "Pub"}

type Input struct {
	Name         string    `json:"name"`
	ExpectedHash string    `json:"expected_inventory_hash"`
	Packages     []Package `json:"packages"`
	Lockfile     string    `json:"lockfile_content"`
	Approved     bool      `json:"approve_external_lookup"`
	Daily        bool      `json:"daily"`
}

func Normalize(in Input) (Inventory, error) {
	inv := Inventory{Packages: []Package{}, Warnings: []string{}, Source: "explicit packages"}
	if in.Lockfile != "" && len(in.Packages) > 0 {
		return inv, errors.New("choose a lockfile or explicit packages, not both")
	}
	if in.Lockfile != "" {
		inv.Source = "package-lock.json"
		if len(in.Lockfile) > 1<<20 {
			return inv, errors.New("lockfile exceeds 1 MiB")
		}
		type entry struct {
			Name         string                     `json:"name"`
			Version      string                     `json:"version"`
			Link         bool                       `json:"link"`
			Dependencies map[string]json.RawMessage `json:"dependencies"`
		}
		var lock struct {
			LockfileVersion int                        `json:"lockfileVersion"`
			Packages        map[string]entry           `json:"packages"`
			Dependencies    map[string]json.RawMessage `json:"dependencies"`
		}
		if err := json.Unmarshal([]byte(in.Lockfile), &lock); err != nil {
			return inv, errors.New("invalid package-lock.json")
		}
		if lock.LockfileVersion < 1 || lock.LockfileVersion > 3 {
			return inv, errors.New("supported lockfiles are package-lock.json versions 1, 2 and 3")
		}
		add := func(name string, e entry) {
			if e.Link || !exactVersion.MatchString(e.Version) {
				inv.Skipped++
				return
			}
			if e.Name != "" {
				name = e.Name
			}
			inv.Packages = append(inv.Packages, Package{Ecosystem: "npm", Name: name, Version: e.Version})
		}
		if lock.LockfileVersion >= 2 {
			if lock.Packages == nil {
				return inv, errors.New("lockfile has no packages map")
			}
			for path, e := range lock.Packages {
				if path == "" {
					continue
				}
				at := strings.LastIndex(path, "node_modules/")
				if at < 0 {
					inv.Skipped++
					continue
				}
				add(path[at+len("node_modules/"):], e)
			}
		} else {
			var walk func(map[string]json.RawMessage, int) error
			visited := 0
			walk = func(deps map[string]json.RawMessage, depth int) error {
				if depth > 100 {
					return errors.New("lockfile dependency nesting exceeds limit")
				}
				for name, raw := range deps {
					visited++
					if visited > 10000 {
						return errors.New("lockfile contains too many entries")
					}
					var e entry
					if json.Unmarshal(raw, &e) != nil {
						return errors.New("malformed lockfile dependency")
					}
					add(name, e)
					if err := walk(e.Dependencies, depth+1); err != nil {
						return err
					}
				}
				return nil
			}
			if err := walk(lock.Dependencies, 0); err != nil {
				return inv, err
			}
		}
	} else {
		inv.Packages = append(inv.Packages, in.Packages...)
	}
	unique := map[string]Package{}
	for _, p := range inv.Packages {
		p.Name = strings.TrimSpace(p.Name)
		p.Version = strings.TrimSpace(p.Version)
		eco, ok := ecosystems[strings.ToLower(strings.TrimSpace(p.Ecosystem))]
		if !ok {
			return inv, fmt.Errorf("unsupported ecosystem %q", p.Ecosystem)
		}
		p.Ecosystem = eco
		if !packageName.MatchString(p.Name) || !exactVersion.MatchString(p.Version) {
			return inv, errors.New("each component needs a valid package name and an exact numeric version; ranges, URLs and tags are not accepted")
		}
		core := strings.SplitN(strings.SplitN(p.Version, "-", 2)[0], "+", 2)[0]
		for _, segment := range strings.Split(core, ".") {
			if strings.EqualFold(segment, "x") {
				return inv, errors.New("wildcard version ranges are not exact versions")
			}
		}
		if eco == "npm" || eco == "crates.io" || eco == "Go" {
			version, err := semver.StrictNewVersion(strings.TrimPrefix(strings.TrimPrefix(p.Version, "v"), "V"))
			if err != nil {
				return inv, fmt.Errorf("%s requires an exact major.minor.patch version; ranges and partial versions are not accepted", eco)
			}
			p.Version = version.String()
			if eco == "Go" {
				p.Version = "v" + p.Version
			}
		}
		if eco == "npm" {
			p.Name = strings.ToLower(p.Name)
		}
		if eco == "PyPI" {
			p.Name = strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(p.Name, "-"))
		}
		unique[digest(p)] = p
	}
	inv.Packages = []Package{}
	for _, p := range unique {
		inv.Packages = append(inv.Packages, p)
	}
	sort.Slice(inv.Packages, func(i, j int) bool {
		a, b := inv.Packages[i], inv.Packages[j]
		return a.Ecosystem+"/"+a.Name+"/"+a.Version < b.Ecosystem+"/"+b.Name+"/"+b.Version
	})
	if len(inv.Packages) == 0 {
		return inv, errors.New("no supported exact-version packages found")
	}
	if len(inv.Packages) > MaxPackages {
		return inv, fmt.Errorf("inventory exceeds %d unique package versions", MaxPackages)
	}
	if inv.Skipped > 0 {
		inv.Warnings = append(inv.Warnings, fmt.Sprintf("%d local, linked or unversioned entries were not checked", inv.Skipped))
	}
	return inv, nil
}
