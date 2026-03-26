package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// ── CPE sources ────────────────────────────────────────────────────────────────
// Each entry must be a URL to a CSV file with at least "vendor" and "product"
// columns.  Add more sources here as they become available.
var cpeDictSources = []string{
	"https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpes.csv",
}

// ── PURL sources ───────────────────────────────────────────────────────────────
// purlSource is a function that, given a technology name and its upstream
// fingerprint, attempts to return a PURL string.  It returns "" if no match
// is found.  Sources are tried in order; the first non-empty result wins
// (unless overridden by manual enrichment.json).
type purlSource func(techName string, fp Fingerprint) string

// purlSources is the ordered list of automatic PURL discovery functions.
// Add new sources here (e.g. PyPI, RubyGems, Docker Hub) as needed.
var purlSources = []purlSource{
	npmPURLSource,
}

// npmJSCategories are wappalyzer category IDs whose technologies are typically
// distributed as npm packages.
var npmJSCategories = map[int]bool{
	12: true, // JavaScript frameworks
	59: true, // JavaScript graphics
	62: true, // UI frameworks
	46: true, // Static site generators (many are npm-based)
	63: true, // Blogging platforms (many are npm-based)
}

// npmPURLSource queries the npm registry to see if a package with this
// technology's name (lower-cased) exists.  It only applies to technologies
// in JavaScript-related categories.
// Source: https://registry.npmjs.org/
func npmPURLSource(techName string, fp Fingerprint) string {
	hasJSCat := false
	for _, cat := range fp.Cats {
		if npmJSCategories[cat] {
			hasJSCat = true
			break
		}
	}
	if !hasJSCat {
		return ""
	}
	name := strings.ToLower(techName)
	resp, err := http.Head("https://registry.npmjs.org/" + name)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	return "pkg:npm/" + name
}

// ── PURL corrections ──────────────────────────────────────────────────────────
// purlCorrections maps technology names to their corrected PURL.
// An empty string means the existing PURL from upstream should be removed.
// These corrections override whatever the upstream webappanalyzer data says.
var purlCorrections = map[string]string{
	// pkg:gem/gitlab is the Ruby REST client, not GitLab itself
	"GitLab": "pkg:docker/gitlab/gitlab-ce",
	// pkg:npm/@grafana/data is the frontend component lib, not the server
	"Grafana": "pkg:docker/grafana/grafana",
	// pkg:npm/kibana doesn't exist as a stand-alone installable pkg
	"Kibana": "pkg:docker/elastic/kibana",
	// pkg:npm/elasticsearch is a JS client, not the search server
	"Elasticsearch": "pkg:docker/elasticsearch/elasticsearch",
	// pkg:generic/redis – pkg:pypi/redis is a client lib, not the server
	"Redis": "pkg:docker/redis/redis",
	// pkg:generic/nginx
	"Nginx": "pkg:docker/nginx/nginx",
	// pkg:generic/apache-httpd
	"Apache HTTP Server": "pkg:docker/httpd/httpd",
	// pkg:generic/postgresql
	"PostgreSQL": "pkg:docker/postgres/postgres",
	// pkg:generic/node
	"Node.js": "pkg:docker/node/node",
	// pkg:generic/php
	"PHP": "pkg:docker/php/php",
	// pkg:generic/bun – bun is a runtime/package-manager itself; no canonical package
	"Bun": "",
	// pkg:generic/deno
	"Deno": "",
	// pkg:npm/ghost – not a stand-alone installable npm package
	"Ghost": "pkg:docker/ghost/ghost",
	// pkg:npm/cloudflare – that's an API client library
	"Cloudflare": "",
}

// ── CPE auto-assign blocklist ─────────────────────────────────────────────────
// skipCPEAutoAssign lists technologies where the CPE dict produces a known
// false positive (a different product that happens to share the same name).
var skipCPEAutoAssign = map[string]bool{
	"Ace":        true, // cpedict: cpe:2.3:a:vmware:ace (VMware virtualizer ≠ ACE editor)
	"Amazon EC2": true, // cpedict: cpe:2.3:a:jenkins:amazon_ec2 (Jenkins plugin ≠ AWS EC2)
	"Amazon S3":  true, // cpedict: cpe:2.3:a:easydigitaldownloads:amazon_s3 (EDD plugin ≠ AWS S3)
	"Datadog":    true, // cpedict: cpe:2.3:a:jenkins:datadog (Jenkins plugin ≠ Datadog SaaS)
	"Eggplant":   true, // cpedict: cpe:2.3:a:jenkins:eggplant (Jenkins plugin ≠ Eggplant testing tool)
}

// ── CPE dictionary types ───────────────────────────────────────────────────────

type cpePair struct {
	vendor  string
	product string
}

type cpeCandidate struct {
	vendor  string
	product string
	reason  string
	score   int
}

var (
	suffixRe = regexp.MustCompile(`(cms|blog|wiki|server|framework|engine|platform|suite|system|library|sdk|api|client|opensource|community|enterprise|pro|plus|lite|free|core)$`)
	domainRe = regexp.MustCompile(`https?://(?:www\.)?([^/]+)`)
)

// normalizeForMatch lowercases s and strips all non-alphanumeric characters.
func normalizeForMatch(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ── CPE dict fetching ──────────────────────────────────────────────────────────

func cpeCachePath(idx int) string {
	return fmt.Sprintf("/tmp/wappalyzer_cpes_%d.csv", idx)
}

func downloadCSV(url, path string) error {
	log.Printf("Downloading CPE source: %s", url)
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// loadCPEDicts fetches and merges all cpeDictSources into a single pair of
// lookup maps.
func loadCPEDicts() (byProduct, byVendor map[string][]cpePair, err error) {
	byProduct = make(map[string][]cpePair)
	byVendor = make(map[string][]cpePair)
	seen := make(map[string]bool)

	for i, src := range cpeDictSources {
		path := cpeCachePath(i)
		if _, serr := os.Stat(path); os.IsNotExist(serr) {
			if dlErr := downloadCSV(src, path); dlErr != nil {
				log.Printf("Skipping CPE source %s: %v", src, dlErr)
				continue
			}
		}
		if perr := parseCPECSV(path, seen, byProduct, byVendor); perr != nil {
			log.Printf("Error parsing CPE source %s: %v", src, perr)
		}
	}

	if len(byProduct) == 0 {
		return nil, nil, fmt.Errorf("no CPE data loaded from any source")
	}
	total := 0
	for _, p := range byProduct {
		total += len(p)
	}
	log.Printf("Loaded %d CPE pairs (%d unique products) from %d source(s)",
		total, len(byProduct), len(cpeDictSources))
	return byProduct, byVendor, nil
}

func parseCPECSV(path string, seen map[string]bool, byProduct, byVendor map[string][]cpePair) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return fmt.Errorf("reading header: %w", err)
	}
	vendorIdx, productIdx := -1, -1
	for i, h := range headers {
		switch strings.TrimSpace(h) {
		case "vendor":
			vendorIdx = i
		case "product":
			productIdx = i
		}
	}
	if vendorIdx < 0 || productIdx < 0 {
		return fmt.Errorf("missing vendor/product columns; found: %v", headers)
	}

	for {
		row, rerr := r.Read()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			continue
		}
		vendor := strings.TrimSpace(row[vendorIdx])
		product := strings.TrimSpace(row[productIdx])
		key := vendor + "\x00" + product
		if seen[key] {
			continue
		}
		seen[key] = true
		pair := cpePair{vendor, product}
		byProduct[normalizeForMatch(product)] = append(byProduct[normalizeForMatch(product)], pair)
		byVendor[normalizeForMatch(vendor)] = append(byVendor[normalizeForMatch(vendor)], pair)
	}
	return nil
}

// ── CPE candidate matching ────────────────────────────────────────────────────

func findCPECandidates(techName, website string, byProduct, byVendor map[string][]cpePair, maxResults int) []cpeCandidate {
	type key struct{ v, p string }
	best := make(map[key]cpeCandidate)

	add := func(v, p, reason string, score int) {
		k := key{v, p}
		if cur, ok := best[k]; !ok || cur.score < score {
			best[k] = cpeCandidate{v, p, reason, score}
		}
	}

	norm := normalizeForMatch(techName)

	for _, pair := range byProduct[norm] {
		add(pair.vendor, pair.product, "exact_product", 100)
	}
	for _, pair := range byVendor[norm] {
		add(pair.vendor, pair.product, "exact_vendor", 90)
	}

	stripped := suffixRe.ReplaceAllString(norm, "")
	if stripped != "" && stripped != norm {
		for _, pair := range byProduct[stripped] {
			add(pair.vendor, pair.product, "stripped_suffix", 80)
		}
		for _, pair := range byVendor[stripped] {
			add(pair.vendor, pair.product, "stripped_vendor", 75)
		}
	}

	if len(norm) >= 4 {
		for k, pairs := range byProduct {
			if strings.Contains(k, norm) && k != norm {
				for _, pair := range pairs {
					add(pair.vendor, pair.product, "product_contains", 60)
				}
			} else if len(k) >= 4 && strings.Contains(norm, k) && k != norm {
				for _, pair := range pairs {
					add(pair.vendor, pair.product, "name_contains_product", 55)
				}
			}
		}
	}

	if website != "" {
		if m := domainRe.FindStringSubmatch(website); len(m) > 1 {
			parts := strings.Split(m[1], ".")
			if len(parts) > 0 {
				dn := normalizeForMatch(parts[0])
				if len(dn) >= 3 {
					for _, pair := range byVendor[dn] {
						add(pair.vendor, pair.product, "website_vendor", 70)
					}
					for _, pair := range byProduct[dn] {
						add(pair.vendor, pair.product, "website_product", 65)
					}
				}
			}
		}
	}

	results := make([]cpeCandidate, 0, len(best))
	for _, c := range best {
		results = append(results, c)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].score != results[j].score {
			return results[i].score > results[j].score
		}
		if results[i].vendor != results[j].vendor {
			return results[i].vendor < results[j].vendor
		}
		return results[i].product < results[j].product
	})
	if len(results) > maxResults {
		results = results[:maxResults]
	}
	return results
}

func buildCPEString(vendor, product string) string {
	return fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", vendor, product)
}

// ── Main enrichment entry point ───────────────────────────────────────────────

// mineCPEsAndPURLs computes in-memory enrichment by combining three layers:
//
//  1. Auto-mined CPEs from cpeDictSources (fill gaps only; upstream always wins).
//  2. PURL corrections from purlCorrections (override wrong upstream PURLs).
//  3. PURL discovery via purlSources (e.g. npm registry; fill gaps only).
//
// The caller's `manual` map (loaded from enrichment.json) is merged last and
// wins over everything.  Nothing is written to disk.
func mineCPEsAndPURLs(apps map[string]Fingerprint, manual map[string]Enrichment, discoverPURLs bool) map[string]Enrichment {
	result := make(map[string]Enrichment, len(apps))

	// Layer 1 – auto-mine CPEs from dictionary sources
	byProduct, byVendor, err := loadCPEDicts()
	if err != nil {
		log.Printf("CPE mining skipped: %v", err)
	} else {
		added := 0
		for techName, app := range apps {
			if skipCPEAutoAssign[techName] {
				continue
			}
			// Only fill gaps: skip if upstream or manual already has a CPE
			manualEntry := manual[techName]
			if app.CPE != "" || manualEntry.CPE != "" {
				continue
			}
			candidates := findCPECandidates(techName, app.Website, byProduct, byVendor, 3)
			var exact []cpeCandidate
			for _, c := range candidates {
				if c.reason == "exact_product" || c.reason == "exact_vendor" {
					exact = append(exact, c)
				}
			}
			if len(exact) == 1 {
				e := result[techName]
				e.CPE = buildCPEString(exact[0].vendor, exact[0].product)
				result[techName] = e
				added++
			}
		}
		log.Printf("Auto-assigned %d CPEs from dictionary", added)
	}

	// Layer 2 – apply PURL corrections (override upstream wrong PURLs)
	for name, newPURL := range purlCorrections {
		e := result[name]
		e.PURL = newPURL // "" means "remove the upstream PURL"
		result[name] = e
	}

	// Layer 3 – PURL discovery via external sources (opt-in, fills gaps only)
	if discoverPURLs {
		discoverMissingPURLs(apps, manual, result)
	}

	// Layer 4 – manual enrichment.json wins over everything above
	for techName, m := range manual {
		e := result[techName]
		if m.CPE != "" {
			e.CPE = m.CPE
		}
		if m.PURL != "" {
			e.PURL = m.PURL
		}
		result[techName] = e
	}

	// Drop entries that ended up fully empty
	for k, v := range result {
		if v.CPE == "" && v.PURL == "" {
			delete(result, k)
		}
	}

	return result
}

// discoverMissingPURLs runs each purlSource in purlSources concurrently for
// technologies that still have no PURL after corrections.  Results fill gaps
// only; they never override upstream or manual data.
func discoverMissingPURLs(apps map[string]Fingerprint, manual map[string]Enrichment, result map[string]Enrichment) {
	type work struct {
		name string
		fp   Fingerprint
	}
	var jobs []work
	for techName, app := range apps {
		// skip if upstream, manual, or a correction already provides a PURL
		if app.PURL != "" {
			continue
		}
		if m := manual[techName]; m.PURL != "" {
			continue
		}
		if r := result[techName]; r.PURL != "" {
			continue
		}
		jobs = append(jobs, work{techName, app})
	}

	type result_ struct {
		name string
		purl string
	}

	const workers = 20
	jobCh := make(chan work, len(jobs))
	resCh := make(chan result_, len(jobs))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobCh {
				for _, src := range purlSources {
					if p := src(j.name, j.fp); p != "" {
						resCh <- result_{j.name, p}
						break
					}
				}
			}
		}()
	}

	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	go func() {
		wg.Wait()
		close(resCh)
	}()

	found := 0
	for r := range resCh {
		e := result[r.name]
		e.PURL = r.purl
		result[r.name] = e
		found++
	}
	if found > 0 {
		log.Printf("Discovered %d PURLs via registry sources", found)
	}
}

// printEnrichmentStats logs a human-readable summary of the enrichment map.
func printEnrichmentStats(result map[string]Enrichment, totalApps int) {
	withCPE, withPURL := 0, 0
	for _, e := range result {
		if e.CPE != "" {
			withCPE++
		}
		if e.PURL != "" {
			withPURL++
		}
	}
	log.Printf("Enrichment totals: %d CPEs, %d PURLs (out of %d technologies)",
		withCPE, withPURL, totalApps)
}

// marshalEnrichmentJSON serialises the enrichment map with sorted keys for
// stable, diffable output.  Exported so callers can write it to disk if needed.
func marshalEnrichmentJSON(m map[string]Enrichment) ([]byte, error) {
	return json.MarshalIndent(m, "", "    ")
}
