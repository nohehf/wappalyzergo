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
)

const cpeDictURL  = "https://raw.githubusercontent.com/tiiuae/cpedict/main/data/cpes.csv"
const cpeDictPath = "/tmp/wappalyzer_cpes.csv"

// skipCPEAutoAssign lists technologies where the auto-miner produces a known
// false positive (e.g. the CPE dict entry belongs to an unrelated product that
// happens to share the same name).
var skipCPEAutoAssign = map[string]bool{
	"Ace":        true, // cpedict has cpe:2.3:a:vmware:ace (VMware Ace, a desktop virtualizer), not the ACE code editor
	"Amazon EC2": true, // cpedict has cpe:2.3:a:jenkins:amazon_ec2 (Jenkins plugin), not AWS EC2
	"Amazon S3":  true, // cpedict has cpe:2.3:a:easydigitaldownloads:amazon_s3 (EDD plugin), not AWS S3
	"Datadog":    true, // cpedict has cpe:2.3:a:jenkins:datadog (Jenkins plugin), not the Datadog SaaS product
	"Eggplant":   true, // cpedict has cpe:2.3:a:jenkins:eggplant (Jenkins plugin), not the Eggplant testing tool
}

// purlCorrections maps technology names to their corrected PURL.
// An empty string means the existing PURL should be removed.
var purlCorrections = map[string]string{
	// pkg:gem/gitlab is the Ruby REST client, not GitLab itself
	"GitLab":             "pkg:docker/gitlab/gitlab-ce",
	// pkg:npm/@grafana/data is the frontend component lib, not the server
	"Grafana":            "pkg:docker/grafana/grafana",
	// pkg:npm/kibana doesn't exist as a stand-alone installable pkg
	"Kibana":             "pkg:docker/elastic/kibana",
	// pkg:npm/elasticsearch is a JS client, not the search server
	"Elasticsearch":      "pkg:docker/elasticsearch/elasticsearch",
	// pkg:generic/redis – pkg:pypi/redis is a client lib, not the server
	"Redis":              "pkg:docker/redis/redis",
	// pkg:generic/nginx
	"Nginx":              "pkg:docker/nginx/nginx",
	// pkg:generic/apache-httpd
	"Apache HTTP Server": "pkg:docker/httpd/httpd",
	// pkg:generic/postgresql
	"PostgreSQL":         "pkg:docker/postgres/postgres",
	// pkg:generic/node
	"Node.js":            "pkg:docker/node/node",
	// pkg:generic/php
	"PHP":                "pkg:docker/php/php",
	// pkg:generic/bun – bun is a runtime/package-manager itself; no canonical package
	"Bun":                "",
	// pkg:generic/deno
	"Deno":               "",
	// pkg:npm/ghost – not a stand-alone installable npm package
	"Ghost":              "pkg:docker/ghost/ghost",
	// pkg:npm/cloudflare – that's an API client library
	"Cloudflare":         "",
}

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

// normalizeForMatch lowercases s and strips all non-alphanumeric characters for
// fuzzy key comparison.
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

func downloadCPEDict() error {
	log.Printf("Downloading CPE dictionary from %s...", cpeDictURL)
	resp, err := http.Get(cpeDictURL) //nolint:noctx
	if err != nil {
		return fmt.Errorf("downloading CPE dict: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CPE dict download: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(cpeDictPath)
	if err != nil {
		return fmt.Errorf("creating CPE dict file: %w", err)
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func loadCPEDict() (byProduct, byVendor map[string][]cpePair, err error) {
	f, ferr := os.Open(cpeDictPath)
	if os.IsNotExist(ferr) {
		if dlErr := downloadCPEDict(); dlErr != nil {
			return nil, nil, dlErr
		}
		f, ferr = os.Open(cpeDictPath)
	}
	if ferr != nil {
		return nil, nil, ferr
	}
	defer f.Close()

	byProduct = make(map[string][]cpePair)
	byVendor = make(map[string][]cpePair)
	seen := make(map[string]bool)

	r := csv.NewReader(f)
	headers, err := r.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("reading CPE CSV header: %w", err)
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
		return nil, nil, fmt.Errorf("CPE CSV missing vendor/product columns, found: %v", headers)
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
		pairKey := vendor + "\x00" + product
		if seen[pairKey] {
			continue
		}
		seen[pairKey] = true

		pair := cpePair{vendor, product}
		kp := normalizeForMatch(product)
		kv := normalizeForMatch(vendor)
		byProduct[kp] = append(byProduct[kp], pair)
		byVendor[kv] = append(byVendor[kv], pair)
	}

	total := 0
	for _, pairs := range byProduct {
		total += len(pairs)
	}
	log.Printf("Loaded %d CPE pairs (%d unique products)", total, len(byProduct))
	return byProduct, byVendor, nil
}

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

	// 1. Exact product match
	for _, pair := range byProduct[norm] {
		add(pair.vendor, pair.product, "exact_product", 100)
	}
	// 2. Exact vendor match
	for _, pair := range byVendor[norm] {
		add(pair.vendor, pair.product, "exact_vendor", 90)
	}
	// 3. Strip common suffixes and retry
	stripped := suffixRe.ReplaceAllString(norm, "")
	if stripped != "" && stripped != norm {
		for _, pair := range byProduct[stripped] {
			add(pair.vendor, pair.product, "stripped_suffix", 80)
		}
		for _, pair := range byVendor[stripped] {
			add(pair.vendor, pair.product, "stripped_vendor", 75)
		}
	}
	// 4. Substring matches (only for names ≥ 4 chars to avoid noise)
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
	// 5. Website domain heuristic
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

// mineAndUpdateEnrichment downloads the CPE dictionary, finds missing CPEs for
// all technologies (auto-confirming only single exact matches to avoid false
// positives), applies PURL corrections, writes the updated enrichment.json, and
// returns the updated in-memory enrichment map for immediate use.
func mineAndUpdateEnrichment(apps map[string]Fingerprint, enrichment map[string]Enrichment, enrichmentPath string) map[string]Enrichment {
	byProduct, byVendor, err := loadCPEDict()
	if err != nil {
		log.Printf("CPE mining skipped: %v", err)
		return enrichment
	}

	changed := 0

	// Find technologies without a CPE and auto-confirm single exact matches.
	for techName, app := range apps {
		if skipCPEAutoAssign[techName] {
			continue
		}
		existing := enrichment[techName]
		if app.CPE != "" || existing.CPE != "" {
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
			cpe := buildCPEString(exact[0].vendor, exact[0].product)
			e := enrichment[techName]
			e.CPE = cpe
			enrichment[techName] = e
			changed++
			log.Printf("CPE added  %-40s  %s", techName, cpe)
		}
	}

	// Apply hard-coded PURL corrections.
	for name, newPURL := range purlCorrections {
		e := enrichment[name]
		if newPURL == "" {
			if e.PURL != "" {
				e.PURL = ""
				enrichment[name] = e
				changed++
				log.Printf("PURL removed  %s", name)
			}
		} else if e.PURL != newPURL {
			e.PURL = newPURL
			enrichment[name] = e
			changed++
			log.Printf("PURL updated  %-40s  %s", name, newPURL)
		}
	}

	// Drop entries that are now fully empty.
	for k, v := range enrichment {
		if v.CPE == "" && v.PURL == "" {
			delete(enrichment, k)
		}
	}

	if changed == 0 {
		log.Printf("No enrichment changes (CPE dict already applied)")
		return enrichment
	}

	// encoding/json sorts map keys alphabetically, so the output is stable.
	data, err := json.MarshalIndent(enrichment, "", "    ")
	if err != nil {
		log.Printf("Could not marshal enrichment: %v", err)
		return enrichment
	}
	if err := os.WriteFile(enrichmentPath, data, 0o666); err != nil {
		log.Printf("Could not write enrichment file: %v", err)
	} else {
		log.Printf("Wrote %d enrichment changes to %s", changed, enrichmentPath)
	}
	return enrichment
}
