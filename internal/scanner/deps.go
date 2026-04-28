package scanner

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/altship-hq/safeclone/internal/report"
)

const osvBatchURL = "https://api.osv.dev/v1/querybatch"

type osvQuery struct {
	Version string `json:"version,omitempty"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Severity []struct {
				Score float64 `json:"score"`
				Type  string  `json:"type"`
			} `json:"severity"`
		} `json:"vulns"`
	} `json:"results"`
}

type depEntry struct {
	name      string
	ecosystem string
	version   string
}

// ScanDependencies checks packages across all supported ecosystems against the OSV vulnerability database.
func ScanDependencies(dir string) ([]report.Vuln, error) {
	var packages []depEntry
	packages = append(packages, parseNpm(dir)...)
	packages = append(packages, parsePyPI(dir)...)
	packages = append(packages, parseGoMod(dir)...)
	packages = append(packages, parseCargo(dir)...)
	packages = append(packages, parseMaven(dir)...)
	packages = append(packages, parseGemfileLock(dir)...)
	packages = append(packages, parseComposer(dir)...)
	packages = append(packages, parseNuGet(dir)...)
	packages = append(packages, parsePubspec(dir)...)
	packages = append(packages, parseMixExs(dir)...)

	if len(packages) == 0 {
		return nil, nil
	}

	req := osvBatchRequest{Queries: make([]osvQuery, len(packages))}
	for i, p := range packages {
		req.Queries[i].Version = p.version
		req.Queries[i].Package.Name = p.name
		req.Queries[i].Package.Ecosystem = p.ecosystem
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(osvBatchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var osvResp osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, err
	}

	var vulns []report.Vuln
	for i, result := range osvResp.Results {
		if len(result.Vulns) == 0 {
			continue
		}
		severity := "medium"
		for _, v := range result.Vulns {
			for _, s := range v.Severity {
				if s.Score > 7 {
					severity = "high"
				}
			}
		}
		vulns = append(vulns, report.Vuln{
			Package:  packages[i].name,
			Count:    len(result.Vulns),
			Severity: severity,
		})
	}
	return vulns, nil
}

// --- npm ---

func parseNpm(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var entries []depEntry
	for name, ver := range pkg.Dependencies {
		entries = append(entries, depEntry{name, "npm", stripNpmRange(ver)})
	}
	for name, ver := range pkg.DevDependencies {
		entries = append(entries, depEntry{name, "npm", stripNpmRange(ver)})
	}
	return entries
}

// stripNpmRange converts semver range strings like "^4.17.4" or "~2.0.0" to "4.17.4".
func stripNpmRange(v string) string {
	v = strings.TrimLeft(v, "^~>=<! ")
	if i := strings.IndexAny(v, " \t"); i != -1 {
		v = v[:i]
	}
	if v == "*" || v == "" || strings.ContainsAny(v, "/:\\") {
		return ""
	}
	return v
}

// --- PyPI ---

func parsePyPI(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		return nil
	}
	var entries []depEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, ver := splitPyPILine(line)
		if name != "" {
			entries = append(entries, depEntry{name, "PyPI", ver})
		}
	}
	return entries
}

// splitPyPILine parses "requests==2.28.0" or "flask>=2.0" into (name, version).
func splitPyPILine(line string) (name, version string) {
	if i := strings.Index(line, "["); i != -1 {
		if j := strings.Index(line, "]"); j != -1 {
			line = line[:i] + line[j+1:]
		}
	}
	idx := strings.IndexAny(line, "=><~!;")
	if idx == -1 {
		return strings.TrimSpace(line), ""
	}
	name = strings.TrimSpace(line[:idx])
	rest := line[idx:]
	if strings.HasPrefix(rest, "==") {
		ver := strings.TrimPrefix(rest, "==")
		if i := strings.IndexAny(ver, ", ;"); i != -1 {
			ver = ver[:i]
		}
		return name, strings.TrimSpace(ver)
	}
	rest = strings.TrimLeft(rest, ">=<~!")
	if i := strings.IndexAny(rest, ", ;"); i != -1 {
		rest = rest[:i]
	}
	return name, strings.TrimSpace(rest)
}

// --- Go modules ---

func parseGoMod(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return nil
	}
	var entries []depEntry
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "//") {
			continue
		}
		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}
		var rest string
		if inBlock {
			rest = line
		} else if strings.HasPrefix(line, "require ") {
			rest = strings.TrimPrefix(line, "require ")
		} else {
			continue
		}
		if i := strings.Index(rest, "//"); i != -1 {
			rest = rest[:i]
		}
		parts := strings.Fields(rest)
		if len(parts) < 2 {
			continue
		}
		ver := strings.TrimPrefix(parts[1], "v")
		entries = append(entries, depEntry{parts[0], "Go", ver})
	}
	return entries
}

// --- Cargo ---

func parseCargo(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return nil
	}
	var entries []depEntry
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[dependencies]" || line == "[dev-dependencies]" || line == "[build-dependencies]" {
			inDeps = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inDeps = false
			continue
		}
		if !inDeps || !strings.Contains(line, "=") {
			continue
		}
		eqIdx := strings.Index(line, "=")
		name := strings.TrimSpace(line[:eqIdx])
		val := strings.TrimSpace(line[eqIdx+1:])
		ver := extractCargoVersion(val)
		if name != "" {
			entries = append(entries, depEntry{name, "crates.io", ver})
		}
	}
	return entries
}

// extractCargoVersion handles both `"1.0"` and `{ version = "1.0", ... }` forms.
func extractCargoVersion(val string) string {
	if strings.HasPrefix(val, `"`) {
		return strings.Trim(val, `"`)
	}
	const marker = "version"
	idx := strings.Index(val, marker)
	if idx == -1 {
		return ""
	}
	rest := strings.TrimLeft(val[idx+len(marker):], ` \t=`)
	if !strings.HasPrefix(rest, `"`) {
		return ""
	}
	rest = rest[1:]
	if end := strings.Index(rest, `"`); end != -1 {
		return rest[:end]
	}
	return ""
}

// --- Maven (Java) ---

func parseMaven(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "pom.xml"))
	if err != nil {
		return nil
	}
	type xmlDep struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
		Scope      string `xml:"scope"`
	}
	var project struct {
		Dependencies []xmlDep `xml:"dependencies>dependency"`
	}
	if xml.Unmarshal(data, &project) != nil {
		return nil
	}
	var entries []depEntry
	for _, d := range project.Dependencies {
		if d.Scope == "test" {
			continue
		}
		name := d.GroupID + ":" + d.ArtifactID
		entries = append(entries, depEntry{name, "Maven", d.Version})
	}
	return entries
}

// --- RubyGems (Gemfile.lock) ---

func parseGemfileLock(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "Gemfile.lock"))
	if err != nil {
		return nil
	}
	var entries []depEntry
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		// blank line or unindented line ends the specs block
		if inSpecs && (line == "" || (len(line) > 0 && line[0] != ' ')) {
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}
		// top-level gem lines have exactly 4 spaces; sub-dependency lines have 6+
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		idx := strings.Index(trimmed, " (")
		if idx == -1 {
			continue
		}
		name := trimmed[:idx]
		ver := strings.TrimRight(trimmed[idx+2:], ")")
		entries = append(entries, depEntry{name, "RubyGems", ver})
	}
	return entries
}

// --- Composer (PHP) ---

func parseComposer(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "composer.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var entries []depEntry
	add := func(name, ver string) {
		// skip platform requirements: "php", "php-64bit", "ext-json", etc.
		if name == "php" || strings.HasPrefix(name, "php-") || strings.HasPrefix(name, "ext-") {
			return
		}
		entries = append(entries, depEntry{name, "Packagist", stripNpmRange(ver)})
	}
	for name, ver := range pkg.Require {
		add(name, ver)
	}
	for name, ver := range pkg.RequireDev {
		add(name, ver)
	}
	return entries
}

// --- NuGet (.NET) ---

func parseNuGet(dir string) []depEntry {
	var entries []depEntry
	// packages.config (legacy format)
	if data, err := os.ReadFile(filepath.Join(dir, "packages.config")); err == nil {
		entries = append(entries, parsePackagesConfig(data)...)
	}
	// SDK-style .csproj files — scan root and one level deep
	for _, pattern := range []string{"*.csproj", "*/*.csproj"} {
		matches, _ := filepath.Glob(filepath.Join(dir, pattern))
		for _, path := range matches {
			entries = append(entries, parseCSProj(path)...)
		}
	}
	return entries
}

func parsePackagesConfig(data []byte) []depEntry {
	type xmlPkg struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	}
	var root struct {
		Packages []xmlPkg `xml:"package"`
	}
	if xml.Unmarshal(data, &root) != nil {
		return nil
	}
	var entries []depEntry
	for _, p := range root.Packages {
		entries = append(entries, depEntry{p.ID, "NuGet", p.Version})
	}
	return entries
}

func parseCSProj(path string) []depEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	type xmlRef struct {
		Include string `xml:"Include,attr"`
		Version string `xml:"Version,attr"`
	}
	var project struct {
		Refs []xmlRef `xml:"ItemGroup>PackageReference"`
	}
	if xml.Unmarshal(data, &project) != nil {
		return nil
	}
	var entries []depEntry
	for _, ref := range project.Refs {
		if ref.Include != "" {
			entries = append(entries, depEntry{ref.Include, "NuGet", ref.Version})
		}
	}
	return entries
}

// --- Pub (Dart/Flutter) ---

func parsePubspec(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "pubspec.yaml"))
	if err != nil {
		return nil
	}
	var entries []depEntry
	inDeps := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line == "dependencies:" || line == "dev_dependencies:" {
			inDeps = true
			continue
		}
		// unindented non-empty line is a new top-level key
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inDeps = false
			continue
		}
		if !inDeps {
			continue
		}
		// top-level dep lines have 2 spaces; nested lines (sdk: flutter) have 4+
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx == -1 {
			continue
		}
		name := strings.TrimSpace(trimmed[:colonIdx])
		ver := strings.TrimSpace(trimmed[colonIdx+1:])
		// skip sdk references and path/git deps
		if ver == "" || strings.ContainsAny(ver, "/\\") || ver == "flutter" {
			continue
		}
		ver = strings.TrimLeft(ver, "^~>=<! ")
		entries = append(entries, depEntry{name, "Pub", ver})
	}
	return entries
}

// --- Hex (Elixir) ---

func parseMixExs(dir string) []depEntry {
	data, err := os.ReadFile(filepath.Join(dir, "mix.exs"))
	if err != nil {
		return nil
	}
	var entries []depEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// dep tuples look like: {:phoenix, "~> 1.6.0"}
		if !strings.HasPrefix(line, "{:") {
			continue
		}
		inner := line[2:]
		commaIdx := strings.Index(inner, ",")
		if commaIdx == -1 {
			continue
		}
		name := strings.TrimSpace(inner[:commaIdx])
		rest := strings.TrimSpace(inner[commaIdx+1:])
		// extract version from the first quoted string
		qStart := strings.Index(rest, `"`)
		if qStart == -1 {
			continue
		}
		rest = rest[qStart+1:]
		qEnd := strings.Index(rest, `"`)
		if qEnd == -1 {
			continue
		}
		ver := strings.TrimLeft(rest[:qEnd], "~>=<! ")
		entries = append(entries, depEntry{name, "Hex", ver})
	}
	return entries
}
