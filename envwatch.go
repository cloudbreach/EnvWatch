package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

/// keywords indicating possible secrets
var secretKeywords = []string{
	"PASSWORD",
	"PASS",
	"SECRET",
	"API_KEY",
	"APIKEY",
	"TOKEN",
	"AWS_SECRET",
	"PRIVATE_KEY",
	"ACCESS_KEY",
	"DB_PASSWORD",
}

// structure for JSON output
type SecretResult struct {
	Source   string `json:"source"`
	File     string `json:"file"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
}

// check if variable name contains secret keyword
func containsSecretKeyword(name string) bool {
	nameUpper := strings.ToUpper(name)

	for _, keyword := range secretKeywords {
		if strings.Contains(nameUpper, keyword) {
			return true
		}
	}

	return false
}

// scan environment variables
func scanEnvVars(results *[]SecretResult) {

	fmt.Println("Scanning environment variables...\n")

	envVars := os.Environ()

	for _, env := range envVars {

		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		if containsSecretKeyword(key) {

			fmt.Printf("Secret detected (ENV): %s = %s\n", key, value)

			*results = append(*results, SecretResult{
				Source:   "environment",
				File:     "system",
				Variable: key,
				Value:    value,
			})
		}
	}
}

// scan a .env file
func scanEnvFile(path string, results *[]SecretResult) {

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")

	for _, line := range lines {

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

		if containsSecretKeyword(key) {

			fmt.Printf("Secret detected (.env): %s = %s (file: %s)\n", key, value, path)

			*results = append(*results, SecretResult{
				Source:   ".env file",
				File:     path,
				Variable: key,
				Value:    value,
			})
		}
	}
}

// recursively scan system for .env files
func scanSystemForEnvFiles(results *[]SecretResult) {

	fmt.Println("\nScanning system for .env files...\n")

	root := "/"

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return nil
		}

		if !info.IsDir() && strings.HasSuffix(info.Name(), ".env") {

			fmt.Printf("Found .env file: %s\n", path)

			scanEnvFile(path, results)
		}

		return nil
	})
}

// export results to JSON
func exportJSON(results []SecretResult) {

	file, err := os.Create("secret_report.json")
	if err != nil {
		fmt.Println("Error creating JSON report")
		return
	}

	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	err = encoder.Encode(results)
	if err != nil {
		fmt.Println("Error writing JSON")
		return
	}

	fmt.Println("\nJSON report saved to secret_report.json")
}

func main() {

	fmt.Println("EnvSecretScanner - Full System Scan")
	fmt.Println("-----------------------------------")

	var results []SecretResult

	// scan environment variables
	scanEnvVars(&results)

	// scan system for .env files
	scanSystemForEnvFiles(&results)

	// export report
	exportJSON(results)
}