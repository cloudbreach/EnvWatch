package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

/* ================== COLORS ================== */

var useColor = true

const (
	ColorReset  = "\033[0m"
	ColorBlue   = "\033[34m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
)

func colorize(color, text string) string {
	if !useColor {
		return text
	}
	return color + text + ColorReset
}

/* ================== FLAGS ================== */

var (
	flagEnvOnly  bool
	flagKeysOnly bool
	flagAWSOnly  bool
	flagNoSystem bool
)

/* ================== GLOBAL COUNTER ================== */

var fileCounter int

/* ================== CONFIG ================== */

var secretKeywords = []string{
	"PASSWORD", "PASS", "SECRET", "API_KEY", "APIKEY",
	"TOKEN", "AWS_SECRET", "PRIVATE_KEY", "ACCESS_KEY", "DB_PASSWORD",
}

var showSecrets bool
var partialMask bool

type SecretResult struct {
	Source   string `json:"source"`
	File     string `json:"file"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
}

type Stats struct {
	TotalSecrets int            `json:"total_secrets"`
	FilesScanned int            `json:"files_scanned"`
	BySource     map[string]int `json:"by_source"`
}

/* ================== INIT ================== */

func init() {
	flag.BoolVar(&showSecrets, "show-secrets", false, "Show full secret values")
	flag.BoolVar(&partialMask, "partial", false, "Partially mask secrets")

	flag.BoolVar(&flagEnvOnly, "env", false, "Scan only .env files")
	flag.BoolVar(&flagKeysOnly, "keys", false, "Scan only key files")
	flag.BoolVar(&flagAWSOnly, "aws", false, "Scan only AWS credentials")
	flag.BoolVar(&flagNoSystem, "no-system", false, "Skip filesystem scan")

	flag.Parse()

	if fi, _ := os.Stdout.Stat(); (fi.Mode() & os.ModeCharDevice) == 0 {
		useColor = false
	}
}

/* ================== HELPERS ================== */

func shouldScanAll() bool {
	return !flagEnvOnly && !flagKeysOnly && !flagAWSOnly
}

func containsSecretKeyword(name string) bool {
	nameUpper := strings.ToUpper(name)
	for _, keyword := range secretKeywords {
		if strings.Contains(nameUpper, keyword) {
			return true
		}
	}
	return false
}

func maybeRedact(value string) string {
	if showSecrets {
		return value
	}
	if partialMask {
		return maskPartial(value)
	}
	return "[REDACTED]"
}

func maskPartial(s string) string {
	if len(s) <= 6 {
		return "***"
	}
	return s[:3] + "..." + s[len(s)-3:]
}

func calculateEntropy(s string) float64 {
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func looksLikeSecret(value string) bool {
	if len(value) < 8 {
		return false
	}

	entropy := calculateEntropy(value)

	hasLetter := false
	hasDigit := false

	for _, c := range value {
		if unicode.IsLetter(c) {
			hasLetter = true
		}
		if unicode.IsDigit(c) {
			hasDigit = true
		}
	}

	return entropy > 3.5 && hasLetter && hasDigit
}

func getHomeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

func recordSecret(results *[]SecretResult, stats *Stats, res SecretResult) {
	*results = append(*results, res)
	stats.TotalSecrets++
	stats.BySource[res.Source]++
}

func printFileHeader(path string) {
	fileCounter++
	fmt.Println(colorize(ColorBlue, fmt.Sprintf("%d. %s", fileCounter, path)))
}

/* ================== SSH DETECTION ================== */

func isSSHPrivateKey(data string) bool {
	return strings.Contains(data, "BEGIN OPENSSH PRIVATE KEY") ||
		strings.Contains(data, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(data, "BEGIN EC PRIVATE KEY")
}

/* ================== SCANNERS ================== */

func scanEnvVars(results *[]SecretResult, stats *Stats) {
	if flagAWSOnly {
		return
	}

	fmt.Println(colorize(ColorYellow, "Scanning environment variables...\n"))

	for _, env := range os.Environ() {

		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		if containsSecretKeyword(key) || looksLikeSecret(value) {
			fmt.Println(colorize(ColorGreen, "-> "+key))

			recordSecret(results, stats, SecretResult{
				Source:   "environment",
				File:     "system",
				Variable: key,
				Value:    maybeRedact(value),
			})
		}
	}
}

func scanEnvFile(path string, results *[]SecretResult, stats *Stats) bool {
	if !(shouldScanAll() || flagEnvOnly) {
		return false
	}

	found := false

	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	for _, line := range strings.Split(string(data), "\n") {

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if containsSecretKeyword(key) || looksLikeSecret(value) {

			if !found {
				printFileHeader(path)
				found = true
			}

			fmt.Println("  " + colorize(ColorGreen, "-> "+key))

			recordSecret(results, stats, SecretResult{
				Source:   ".env file",
				File:     path,
				Variable: key,
				Value:    maybeRedact(value),
			})
		}
	}

	return found
}

func scanKeyFile(path string, results *[]SecretResult, stats *Stats) bool {
	if !(shouldScanAll() || flagKeysOnly) {
		return false
	}

	dataBytes, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	data := string(dataBytes)

	if strings.Contains(data, "PRIVATE KEY") || isSSHPrivateKey(data) {

		printFileHeader(path)

		recordSecret(results, stats, SecretResult{
			Source:   "key file",
			File:     path,
			Variable: filepath.Base(path),
			Value:    maybeRedact(data),
		})

		return true
	}

	return false
}

func scanAWS(results *[]SecretResult, stats *Stats) {
	if !(shouldScanAll() || flagAWSOnly) {
		return
	}

	home := getHomeDir()

	scanAWSFile(filepath.Join(home, ".aws", "credentials"), results, stats)
	scanAWSFile(filepath.Join(home, ".aws", "config"), results, stats)
}

func scanAWSFile(path string, results *[]SecretResult, stats *Stats) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	section := ""
	printed := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}

		if !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if containsSecretKeyword(key) || looksLikeSecret(value) {

			if !printed {
				printFileHeader(path)
				printed = true
			}

			fmt.Println("  " + colorize(ColorGreen, "-> "+key))

			recordSecret(results, stats, SecretResult{
				Source:   "aws file",
				File:     path,
				Variable: section + ":" + key,
				Value:    maybeRedact(value),
			})
		}
	}
}

func scanSSH(results *[]SecretResult, stats *Stats) {
	if !(shouldScanAll() || flagKeysOnly) {
		return
	}

	sshDir := filepath.Join(getHomeDir(), ".ssh")

	filepath.Walk(sshDir, func(path string, info os.FileInfo, err error) error {

		if err != nil || info.IsDir() {
			return nil
		}

		stats.FilesScanned++

		scanKeyFile(path, results, stats)

		return nil
	})
}

func scanSystem(results *[]SecretResult, stats *Stats) {
	if flagNoSystem {
		return
	}

	root := getHomeDir()

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if err != nil || info.IsDir() {
			return nil
		}

		stats.FilesScanned++

		name := strings.ToLower(info.Name())

		if strings.HasSuffix(name, ".env") {
			scanEnvFile(path, results, stats)
		}
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".key") {
			scanKeyFile(path, results, stats)
		}

		return nil
	})
}

/* ================== MAIN ================== */

func main() {

	fmt.Println(`
███████╗███╗   ██╗██╗   ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔════╝████╗  ██║██║   ██║██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
█████╗  ██╔██╗ ██║██║   ██║██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔══╝  ██║╚██╗██║╚██╗ ██╔╝██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
███████╗██║ ╚████║ ╚████╔╝ ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚══════╝╚═╝  ╚═══╝  ╚═══╝   ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝

        🔍 EnvWatch  |  A Go utility that scans your system for exposed secrets
--------------------------------------------------
`)
	fmt.Println("--------------------------------------------------")

	var results []SecretResult
	stats := Stats{BySource: make(map[string]int)}

	scanEnvVars(&results, &stats)
	scanSystem(&results, &stats)
	scanAWS(&results, &stats)
	scanSSH(&results, &stats)

	fmt.Println("\n" + colorize(ColorYellow, "📊 Scan Summary"))
	fmt.Println("--------------------------------------------------")

	fmt.Println(colorize(ColorYellow, fmt.Sprintf("Total secrets found: %d", stats.TotalSecrets)))
	fmt.Println(colorize(ColorYellow, fmt.Sprintf("Total files scanned: %d\n", stats.FilesScanned)))

	fmt.Println("Breakdown by source:")
	for source, count := range stats.BySource {
		fmt.Printf("  %-15s : %d\n", source, count)
	}

	reportFile := "secret_report.json"
	f, err := os.Create(reportFile)
	if err != nil {
		fmt.Println("Error creating report file:", err)
		return
	}
	defer f.Close()

	reportData := map[string]interface{}{
		"stats":   stats,
		"secrets": results,
	}

	jsonData, err := json.MarshalIndent(reportData, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	_, err = f.Write(jsonData)
	if err != nil {
		fmt.Println("Error writing report file:", err)
		return
	}

	fmt.Println(colorize(ColorYellow, "\n✅ Secret report saved to "+reportFile))
}