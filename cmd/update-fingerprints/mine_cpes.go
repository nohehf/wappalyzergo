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
	"time"
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

// ── PURL dictionary sources ────────────────────────────────────────────────────
// purlDictSource describes a package registry whose complete package list can be
// downloaded once (and cached like CPE dicts) and used to auto-discover PURLs by
// matching normalised technology names against normalised package names.
type purlDictSource struct {
	URL         string
	CachePath   string // /tmp path for the downloaded file
	PURLScheme  string // e.g. "gem", "pypi", "composer"
	FetchHeader string // optional HTTP Accept header for the request
	// parse extracts a map of normalised-name → canonical-name-for-PURL.
	// For single-component registries (gem, pypi) canonical == lowercase name.
	// For vendor/package registries (composer) canonical == "vendor/package".
	parse func(data []byte) (map[string]string, error)
}

// purlDictSources lists all static-file package registries to mine for PURLs.
// Add new ecosystems here (e.g. cargo, nuget, hex) as they become available.
var purlDictSources = []purlDictSource{
	{
		URL:        "https://index.rubygems.org/names",
		CachePath:  "/tmp/wappalyzer_purls_gem.txt",
		PURLScheme: "gem",
		parse:      parsePURLDictTextLines,
	},
	{
		URL:         "https://pypi.org/simple/",
		CachePath:   "/tmp/wappalyzer_purls_pypi.json",
		PURLScheme:  "pypi",
		FetchHeader: "application/vnd.pypi.simple.v1+json",
		parse:       parsePURLDictPyPI,
	},
	{
		URL:        "https://packagist.org/packages/list.json",
		CachePath:  "/tmp/wappalyzer_purls_composer.json",
		PURLScheme: "composer",
		parse:      parsePURLDictPackagist,
	},
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
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
	defer func() { _ = f.Close() }()

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

// ── PURL dict fetching and parsing ────────────────────────────────────────────

func downloadPURLDict(src purlDictSource) error {
	log.Printf("Downloading PURL dict for %s: %s", src.PURLScheme, src.URL)
	req, err := http.NewRequest(http.MethodGet, src.URL, nil) //nolint:noctx
	if err != nil {
		return err
	}
	if src.FetchHeader != "" {
		req.Header.Set("Accept", src.FetchHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", src.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", src.URL, resp.StatusCode)
	}
	f, err := os.Create(src.CachePath)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, resp.Body)
	if cerr := f.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// loadPURLDicts downloads (if not cached) and parses every purlDictSource,
// returning a map of PURLScheme → {normalised-name → canonical-name}.
func loadPURLDicts() map[string]map[string]string {
	result := make(map[string]map[string]string, len(purlDictSources))
	for _, src := range purlDictSources {
		if _, serr := os.Stat(src.CachePath); os.IsNotExist(serr) {
			if dlErr := downloadPURLDict(src); dlErr != nil {
				log.Printf("Skipping PURL dict for %s: %v", src.PURLScheme, dlErr)
				continue
			}
		}
		data, err := os.ReadFile(src.CachePath)
		if err != nil {
			log.Printf("Cannot read PURL dict %s: %v", src.CachePath, err)
			continue
		}
		dict, err := src.parse(data)
		if err != nil {
			log.Printf("Cannot parse PURL dict for %s: %v", src.PURLScheme, err)
			continue
		}
		result[src.PURLScheme] = dict
		log.Printf("Loaded %d %s packages from PURL dict", len(dict), src.PURLScheme)
	}
	return result
}

// parsePURLDictTextLines handles plain-text registries where each line is one
// package name (e.g. RubyGems /names endpoint).  Lines beginning with "---"
// (compact-index document separator) are silently skipped.
func parsePURLDictTextLines(data []byte) (map[string]string, error) {
	dict := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "---") {
			continue
		}
		norm := normalizeForMatch(name)
		if norm == "" {
			continue
		}
		if _, exists := dict[norm]; !exists {
			dict[norm] = name
		}
	}
	return dict, nil
}

// parsePURLDictPyPI handles the PyPI Simple JSON API response
// (Accept: application/vnd.pypi.simple.v1+json).
// Canonical names are lowercased per PEP 625 (underscores → hyphens).
func parsePURLDictPyPI(data []byte) (map[string]string, error) {
	var resp struct {
		Projects []struct {
			Name string `json:"name"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal PyPI simple JSON: %w", err)
	}
	dict := make(map[string]string, len(resp.Projects))
	for _, p := range resp.Projects {
		if p.Name == "" {
			continue
		}
		// Canonical PURL form: lowercase, underscores normalised to hyphens.
		canonical := strings.ToLower(strings.ReplaceAll(p.Name, "_", "-"))
		norm := normalizeForMatch(p.Name)
		if norm != "" {
			if _, exists := dict[norm]; !exists {
				dict[norm] = canonical
			}
		}
	}
	return dict, nil
}

// parsePURLDictPackagist handles the Packagist packages/list.json format where
// every entry is "vendor/package".  The lookup key is the normalised package
// part; when multiple packages share that key, a self-named entry
// (vendor == package, e.g. "laravel/laravel") is preferred.
func parsePURLDictPackagist(data []byte) (map[string]string, error) {
	var resp struct {
		PackageNames []string `json:"packageNames"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal Packagist list JSON: %w", err)
	}
	type entry struct {
		full      string
		selfNamed bool
	}
	byNorm := make(map[string]entry, len(resp.PackageNames))
	for _, fullName := range resp.PackageNames {
		parts := strings.SplitN(fullName, "/", 2)
		if len(parts) != 2 {
			continue
		}
		vendor, pkg := parts[0], parts[1]
		norm := normalizeForMatch(pkg)
		if norm == "" {
			continue
		}
		self := vendor == pkg
		if existing, ok := byNorm[norm]; !ok || (!existing.selfNamed && self) {
			byNorm[norm] = entry{fullName, self}
		}
	}
	dict := make(map[string]string, len(byNorm))
	for norm, e := range byNorm {
		dict[norm] = e.full
	}
	return dict, nil
}

// ── PURL category skip-list ────────────────────────────────────────────────────
// skipDictCategories lists Wappalyzer category IDs for which dict-based PURL
// auto-assignment should never be attempted:
//   - JavaScript / frontend ecosystem → npm is the right package manager
//   - Infrastructure (CDN, servers, containers …) → no installable package identity
//   - SaaS / hosted services → Wappalyzer detects the embedded JS or API call,
//     not the server package; any gem/pypi/composer package with the same name
//     is merely a client SDK for the service.
var skipDictCategories = map[int]bool{
	// JavaScript ecosystem
	5:   true, // Widgets
	12:  true, // JavaScript frameworks
	14:  true, // Video players
	17:  true, // Font scripts
	24:  true, // Rich text editors
	25:  true, // JavaScript graphics
	26:  true, // Mobile frameworks
	35:  true, // Maps
	57:  true, // Static site generators
	59:  true, // JavaScript libraries
	66:  true, // UI frameworks
	83:  true, // Browser fingerprinting
	// Infrastructure
	22:  true, // Web servers
	23:  true, // Caching
	28:  true, // Operating systems
	31:  true, // CDN
	33:  true, // Web server extensions
	37:  true, // Network devices
	38:  true, // Media servers
	39:  true, // Webcams
	45:  true, // Control systems
	48:  true, // Network storage
	60:  true, // Containers
	62:  true, // PaaS
	63:  true, // IaaS
	64:  true, // Reverse proxies
	65:  true, // Load balancers
	// SaaS / hosted services
	10:  true, // Analytics
	32:  true, // Marketing automation
	36:  true, // Advertising
	41:  true, // Payment processors
	42:  true, // Tag managers
	52:  true, // Live chat
	53:  true, // CRM
	54:  true, // SEO
	55:  true, // Accounting
	56:  true, // Cryptominers
	58:  true, // User onboarding
	67:  true, // Cookie compliance
	68:  true, // Accessibility
	70:  true, // SSL/TLS certificate authorities
	71:  true, // Affiliate programs
	72:  true, // Appointment scheduling
	73:  true, // Surveys
	74:  true, // A/B Testing
	75:  true, // Email
	76:  true, // Personalisation
	77:  true, // Retargeting
	78:  true, // RUM
	79:  true, // Geolocation
	// Newer SaaS / service categories
	84:  true, // Loyalty & rewards
	85:  true, // Feature management
	86:  true, // Segmentation
	88:  true, // Hosting
	89:  true, // Translation
	90:  true, // Reviews
	91:  true, // Buy now pay later
	93:  true, // Reservations & delivery
	94:  true, // Referral marketing
	95:  true, // Digital asset management
	96:  true, // Content curation
	97:  true, // Customer data platform
	99:  true, // Shipping carriers
	100: true, // Shopify apps
	101: true, // Recruitment & staffing
	102: true, // Returns
	103: true, // Livestreaming
	104: true, // Ticket booking
	105: true, // Augmented reality
	106: true, // Cross border ecommerce
	107: true, // Fulfilment
	108: true, // Ecommerce frontends
	111: true, // Fundraising & donations
}

// ── PURL registry verification ──────────────────────────────────────────────
// verifyCache avoids redundant API calls within a single run.
var verifyCache sync.Map // key: "scheme/canonical" → bool

// verifyPURLWithRegistry confirms that a package is genuinely the technology
// being detected (not just a coincidentally-named or client-SDK package) by:
//  1. Fetching the package's registry metadata (one API call).
//  2. Requiring that at least one homepage/source URL shares a domain with the
//     tech's website.
//  3. Rejecting packages whose description identifies them as a client SDK /
//     API wrapper for the service (e.g. "Ruby client for the Algolia API").
//
// Returns false when the tech has no website, the package has no homepage
// metadata, the domains don't match, or the description is SDK-like.
func verifyPURLWithRegistry(canonical, scheme, techWebsite string) bool {
	if techWebsite == "" {
		return false
	}
	cacheKey := scheme + "/" + canonical
	if v, ok := verifyCache.Load(cacheKey); ok {
		return v.(bool)
	}
	info := fetchPackageInfo(canonical, scheme)
	// Reject packages that describe themselves as a client SDK for a service.
	if looksLikeSDK(info.Desc) {
		verifyCache.Store(cacheKey, false)
		return false
	}
	result := false
	for _, hp := range info.URLs {
		if domainsMatch(hp, techWebsite) {
			result = true
			break
		}
	}
	verifyCache.Store(cacheKey, result)
	return result
}

// pkgInfo holds the homepage URLs and description fetched from a registry.
type pkgInfo struct {
	URLs []string
	Desc string
}

// sdkPhrases are substrings that reliably indicate a client SDK / API wrapper
// rather than the canonical installable package for a technology.
var sdkPhrases = []string{
	// Explicit SDK / client terminology.
	"sdk for", "client for", "wrapper for", "binding for", "bindings for",
	"ruby client", "python client", "go client", "java client", "php client",
	"api client", "api wrapper", "rest client",
	"ruby sdk", "python sdk", "go sdk", "java sdk", "php sdk",
	"official client", "official sdk",
	// Softer phrasing that still indicates a library for an external service.
	"library to access", "interface for the", "interface to the",
	"notifier for", "integration for", "client library",
	"library for interacting", "module for communicating",
	// Language-specific SDK descriptions that omit the word "client/sdk".
	" for python.", " for ruby.", " for go.", " for java.", " for node.",
}

// skipPURLDictAutoAssign prevents specific technology names from receiving
// auto-discovered PURLs from the dict sources when automated heuristics are
// insufficient to rule out false positives (e.g. SaaS services that publish
// an official gem/pypi with the service's own domain as homepage, but whose
// description doesn't use standard SDK / client language).
var skipPURLDictAutoAssign = map[string]bool{
	// Error tracking / monitoring SaaS – detected via JS embed, not Ruby gem/pypi.
	"Rollbar":      true,
	"Honeybadger":  true,
	"Bugsnag":      true,
	"Raygun":       true,
	// Bug / issue tracking SaaS – detected via embedded widget.
	"BugHerd":      true,
	// Ecommerce / content SaaS whose gem/pypi is a client SDK.
	"Kajabi":       true,
	"Searchspring": true,
	"Swiftype":     true,
	"Constructor.io": true,
	"Contentstack": true,
	"ButterCMS":    true,
	"ColorMeShop":  true,
	"Mirakl":       true,
	"Nacelle":      true,
	"Nimbu":        true,
	"Selly":        true,
	"Tictail":      true,
	"Haravan":      true,
	// Website builder / CMS SaaS.
	"Webflow":      true,
	"Scrivito":     true,
	// CAPTCHA / bot-protection services – always detected via JS embed;
	// server-side verification libraries exist for many languages so no single
	// package is canonical.
	"ARCaptcha":    true,
	"Altcha":       true,
	"hCaptcha":     true,
	"VAPTCHA":      true,
	"ReCaptcha":    true,
	// Security / auth SaaS.
	"Sqreen":       true,
	"PerimeterX":   true,
	"Status.io":    true,
	"Conduit":      true,
	"JumpCloud":    true,
	// Developer tools / AI SaaS.
	"Replit":       true,
	"Code Climate": true,
	"Keybase":      true,
	"Clarifai":     true,
	"Appwrite":     true, // BaaS – deployed via Docker, not gem
	// Misc SaaS tools whose SDK gem/pypi passes all other filters.
	"CleanTalk":    true,
	"Clicksign":    true,
	"Trezor":       true,
	"Mopinion":     true,
	"Homestead":    true,
	"Livefyre":     true,
	// JavaScript technologies that lack a JS-specific Wappalyzer category.
	// Their canonical PURL should be npm, not composer/gem/pypi.
	"PDF.js":      true,
	"CodeMirror":  true, // JS code editor, composer is a community wrapper
	"Summernote":  true, // JS rich-text editor, composer is a community wrapper
	"Wordfence":   true, // WordPress plugin, not a Python package
	// Technologies where the matched package belongs to a different project
	// that coincidentally shares the name.
	"Macaron":     true, // Go web framework; pypi/macaron is a Python SQLite ORM
	"Gnuboard":    true, // Korean PHP CMS; pypi/gnuboard is unexpected
	// SaaS services whose SDK package has the service's own domain as homepage
	// and whose description doesn't use standard SDK/client language.
	"Clever":         true, // SaaS EdTech; composer/clever is their PHP wrapper
	"Imagekit":       true, // SaaS image CDN; composer is their PHP library
	"Evernote":       true, // SaaS notes; composer is their PHP SDK
	"FraudLabs Pro":  true, // SaaS anti-fraud; composer is their PHP SDK
}

// looksLikeSDK returns true when a package description identifies the package
// as a client library or SDK for an external service.
func looksLikeSDK(desc string) bool {
	d := strings.ToLower(desc)
	for _, p := range sdkPhrases {
		if strings.Contains(d, p) {
			return true
		}
	}
	return false
}

var registryClient = &http.Client{Timeout: 10 * time.Second}

// fetchPackageInfo calls the registry metadata API once and returns the
// package's homepage/source URLs and a short description.
func fetchPackageInfo(canonical, scheme string) pkgInfo {
	switch scheme {
	case "pypi":
		resp, err := registryClient.Get("https://pypi.org/pypi/" + canonical + "/json") //nolint:noctx
		if err != nil || resp.StatusCode != http.StatusOK {
			return pkgInfo{}
		}
		defer resp.Body.Close()
		var data struct {
			Info struct {
				HomePage    string            `json:"home_page"`
				Summary     string            `json:"summary"`
				ProjectURLs map[string]string `json:"project_urls"`
			} `json:"info"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return pkgInfo{}
		}
		var urls []string
		if hp := data.Info.HomePage; hp != "" && hp != "None" && hp != "UNKNOWN" {
			urls = append(urls, hp)
		}
		for _, u := range data.Info.ProjectURLs {
			if u != "" && u != "UNKNOWN" {
				urls = append(urls, u)
			}
		}
		return pkgInfo{URLs: urls, Desc: data.Info.Summary}

	case "gem":
		resp, err := registryClient.Get("https://rubygems.org/api/v1/gems/" + canonical + ".json") //nolint:noctx
		if err != nil || resp.StatusCode != http.StatusOK {
			return pkgInfo{}
		}
		defer resp.Body.Close()
		var data struct {
			HomepageURI   string `json:"homepage_uri"`
			SourceCodeURI string `json:"source_code_uri"`
			Info          string `json:"info"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return pkgInfo{}
		}
		var urls []string
		if data.HomepageURI != "" {
			urls = append(urls, data.HomepageURI)
		}
		if data.SourceCodeURI != "" {
			urls = append(urls, data.SourceCodeURI)
		}
		return pkgInfo{URLs: urls, Desc: data.Info}

	case "composer":
		resp, err := registryClient.Get("https://packagist.org/packages/" + canonical + ".json") //nolint:noctx
		if err != nil || resp.StatusCode != http.StatusOK {
			return pkgInfo{}
		}
		defer resp.Body.Close()
		var outer struct {
			Package struct {
				Repository  string `json:"repository"`
				Description string `json:"description"`
				Versions    map[string]struct {
					Homepage string `json:"homepage"`
					Source   struct {
						URL string `json:"url"`
					} `json:"source"`
				} `json:"versions"`
			} `json:"package"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&outer); err != nil {
			return pkgInfo{}
		}
		var urls []string
		if outer.Package.Repository != "" {
			urls = append(urls, outer.Package.Repository)
		}
		for _, v := range outer.Package.Versions {
			if v.Homepage != "" {
				urls = append(urls, v.Homepage)
			}
			if v.Source.URL != "" {
				urls = append(urls, v.Source.URL)
			}
			break // first version is enough
		}
		return pkgInfo{URLs: urls, Desc: outer.Package.Description}
	}
	return pkgInfo{}
}

var (
	domainExtractRe  = regexp.MustCompile(`(?i)https?://(?:www\.)?([^/?#\s]+)`)
	// Anchored: matches github.com/ORG only at the beginning of the URL.
	githubURLOrgRe   = regexp.MustCompile(`(?i)^https?://github\.com/([^/?#\s./]+)`)
	gitlabURLOrgRe   = regexp.MustCompile(`(?i)^https?://gitlab\.com/([^/?#\s./]+)`)
	// Matches user/org-site pages: USER.github.io/... or USER.github.com/...
	githubPagesOrgRe = regexp.MustCompile(`(?i)^https?://([^/?#\s./]+)\.github(?:\.io|\.com)/`)
)

// codeHostDomains are code-hosting platforms whose sub-domains (user pages)
// must NOT be treated as ordinary sub-domains of the host itself.
var codeHostDomains = map[string]bool{
	"github.com": true, "gitlab.com": true, "bitbucket.org": true,
}

// extractDomain strips scheme, www, and path from a URL to give a bare host.
func extractDomain(rawURL string) string {
	if m := domainExtractRe.FindStringSubmatch(rawURL); len(m) > 1 {
		return strings.ToLower(strings.TrimSuffix(m[1], "."))
	}
	return ""
}

// extractGitHubOrg returns the organisation (or user) name from a GitHub /
// GitLab URL.  The regexes are all anchored to the beginning of the URL to
// prevent matching the PATH portion of GitHub Pages URLs like
// user.github.com/repo (where a naive search for "github.com/" would find
// "repo" in the path rather than "user" from the host).
//
// Handles:
//   - https://github.com/ORG/repo   → "ORG"
//   - https://USER.github.io/...    → "USER"
//   - https://USER.github.com/...   → "USER"
//   - https://gitlab.com/ORG/repo   → "ORG"
func extractGitHubOrg(rawURL string) string {
	if m := githubURLOrgRe.FindStringSubmatch(rawURL); len(m) > 1 {
		return m[1]
	}
	if m := gitlabURLOrgRe.FindStringSubmatch(rawURL); len(m) > 1 {
		return m[1]
	}
	if m := githubPagesOrgRe.FindStringSubmatch(rawURL); len(m) > 1 {
		return m[1]
	}
	return ""
}

// isForgeURL returns true when the URL is hosted on a code-forge platform
// (github.com, gitlab.com, github.io/user pages, etc.).
func isForgeURL(rawURL string) bool {
	d := extractDomain(rawURL)
	if codeHostDomains[d] {
		return true
	}
	return strings.HasSuffix(d, ".github.io") ||
		strings.HasSuffix(d, ".github.com") ||
		strings.HasSuffix(d, ".gitlab.io")
}

// domainsMatch returns true when two URLs share the same effective domain.
//
// Rules (applied in order):
//  1. Forge-hosted tech website: compare GitHub/GitLab org names exactly.
//  2. Forge-hosted package URL with non-forge tech website: compare the org
//     name against the domain stem using substring, but both strings must be
//     at least minOrgMatchLen characters to prevent short common-word matches.
//  3. Regular domain equality / sub-domain check (code-hosts excluded from the
//     HasSuffix check to avoid user.github.com ≡ github.com).
const minOrgMatchLen = 7

func domainsMatch(packageURL, techURL string) bool {
	pIsForge := isForgeURL(packageURL)
	tIsForge := isForgeURL(techURL)
	pd := extractDomain(packageURL)
	td := extractDomain(techURL)
	if pd == "" || td == "" {
		return false
	}

	// Case 1: tech website is forge-hosted → compare orgs exactly.
	if tIsForge {
		if !pIsForge {
			return false
		}
		tOrg := normalizeForMatch(extractGitHubOrg(techURL))
		pOrg := normalizeForMatch(extractGitHubOrg(packageURL))
		return tOrg != "" && pOrg != "" && tOrg == pOrg
	}

	// Case 2: package is forge-hosted, tech has a real website → fuzzy org match.
	if pIsForge {
		org := normalizeForMatch(extractGitHubOrg(packageURL))
		stem := td
		if idx := strings.LastIndex(stem, "."); idx >= 0 {
			stem = stem[:idx]
		}
		stemNorm := normalizeForMatch(stem)
		// Both the org name and the domain stem must be long enough to be specific.
		if len(org) < minOrgMatchLen || len(stemNorm) < minOrgMatchLen {
			return false
		}
		return strings.Contains(stemNorm, org) || strings.Contains(org, stemNorm)
	}

	// Case 3: neither is forge-hosted → regular domain / sub-domain comparison.
	// Exclude code-host domains from the HasSuffix check so that
	// user.github.com is NOT treated as a sub-domain of github.com.
	if pd == td {
		return true
	}
	if !codeHostDomains[td] && strings.HasSuffix(pd, "."+td) {
		return true
	}
	if !codeHostDomains[pd] && strings.HasSuffix(td, "."+pd) {
		return true
	}
	return false
}

// ecosystemFromWebsite returns the PURL scheme most likely associated with a
// technology based on its official website URL, or "" if unknown.
func ecosystemFromWebsite(website string) string {
	if website == "" {
		return ""
	}
	w := strings.ToLower(website)
	switch {
	case strings.Contains(w, "pypi.org"):
		return "pypi"
	case strings.Contains(w, "rubygems.org"):
		return "gem"
	case strings.Contains(w, "packagist.org"):
		return "composer"
	case strings.Contains(w, "npmjs.com"):
		return "npm"
	case strings.Contains(w, "crates.io"):
		return "cargo"
	case strings.Contains(w, "hex.pm"):
		return "hex"
	case strings.Contains(w, "nuget.org"):
		return "nuget"
	}
	return ""
}

// makeDictPURLSource returns a purlSource backed by all loaded PURL dicts.
// For each candidate match it:
//  1. Skips technologies whose categories are in skipDictCategories.
//  2. Looks up the normalised tech name in each ecosystem dict.
//  3. Verifies the match by comparing the package's registry homepage domain
//     with the tech's website domain (fetchPackageHomepages + domainsMatch).
//
// Only matches that pass the homepage verification are returned, ensuring
// zero false positives from coincidental name collisions across ecosystems.
func makeDictPURLSource(dicts map[string]map[string]string) purlSource {
	return func(techName string, fp Fingerprint) string {
		// Skip techs on the explicit false-positive blocklist.
		if skipPURLDictAutoAssign[techName] {
			return ""
		}
		// Skip techs whose categories signal a different/non-package ecosystem.
		for _, cat := range fp.Cats {
			if skipDictCategories[cat] {
				return ""
			}
		}

		norm := normalizeForMatch(techName)
		if norm == "" {
			return ""
		}
		preferred := ecosystemFromWebsite(fp.Website)

		tryDict := func(scheme string) string {
			dict, ok := dicts[scheme]
			if !ok {
				return ""
			}
			canonical, ok := dict[norm]
			if !ok {
				return ""
			}
			if !verifyPURLWithRegistry(canonical, scheme, fp.Website) {
				return ""
			}
			return "pkg:" + scheme + "/" + canonical
		}

		// Try website-hinted ecosystem first.
		if preferred != "" {
			if p := tryDict(preferred); p != "" {
				return p
			}
		}
		// Fall back through declared source order.
		for _, src := range purlDictSources {
			if src.PURLScheme == preferred {
				continue
			}
			if p := tryDict(src.PURLScheme); p != "" {
				return p
			}
		}
		return ""
	}
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

	// Layer 3 – PURL discovery via external sources (opt-in, fills gaps only).
	// Combine function-based sources (e.g. npm live query) with dict-based
	// sources (gem, pypi, composer) loaded from static registry snapshots.
	if discoverPURLs {
		allSources := append([]purlSource{}, purlSources...)
		dicts := loadPURLDicts()
		if len(dicts) > 0 {
			allSources = append(allSources, makeDictPURLSource(dicts))
		}
		discoverMissingPURLs(apps, manual, result, allSources)
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

// discoverMissingPURLs runs each source in sources concurrently for
// technologies that still have no PURL after corrections.  Results fill gaps
// only; they never override upstream or manual data.
func discoverMissingPURLs(apps map[string]Fingerprint, manual map[string]Enrichment, result map[string]Enrichment, sources []purlSource) {
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
				for _, src := range sources {
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
