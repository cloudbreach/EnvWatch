package main

import (
	"bufio"
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

// get home directory
func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
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

		if containsSecretKeyword(key) {

			fmt.Printf("Secret detected (ENV): %s\n", key)

			*results = append(*results, SecretResult{
				Source:   "environment",
				File:     "system",
				Variable: key,
				Value:    "[REDACTED]",
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

			fmt.Printf("Secret detected (.env): %s (file: %s)\n", key, path)

			*results = append(*results, SecretResult{
				Source:   ".env file",
				File:     path,
				Variable: key,
				Value:    value,
			})
		}
	}
}

// scan YAML files
func scanYAMLFile(path string, results *[]SecretResult) {

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

		if !strings.Contains(line, ":") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if containsSecretKeyword(key) {

			fmt.Printf("Secret detected (YAML): %s (%s)\n", key, path)

			*results = append(*results, SecretResult{
				Source:   "yaml file",
				File:     path,
				Variable: key,
				Value:    value,
			})
		}
	}
}

// scan key files (.pem / .key)
func scanKeyFile(path string, results *[]SecretResult) {

	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	content := string(data)

	if strings.Contains(content, "PRIVATE KEY") {

		fmt.Printf("Private key detected: %s\n", path)

		*results = append(*results, SecretResult{
			Source:   "key file",
			File:     path,
			Variable: filepath.Base(path),
			Value:    "[PRIVATE KEY DETECTED]",
		})
	}
}

// scan AWS credentials/config files
func scanAWSFile(path string, results *[]SecretResult) {

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	fmt.Printf("Scanning AWS file: %s\n", path)

	scanner := bufio.NewScanner(file)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line
			continue
		}

		if !strings.Contains(line, "=") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])

		if containsSecretKeyword(key) ||
			strings.Contains(strings.ToLower(key), "access_key") {

			fmt.Printf("Secret detected (AWS): %s (%s)\n", key, path)

			*results = append(*results, SecretResult{
				Source:   "aws file",
				File:     path,
				Variable: currentSection + ":" + key,
				Value:    "[REDACTED]",
			})
		}
	}
}

// scan common credential files
func scanCommonCredentialFiles(results *[]SecretResult) {

	fmt.Println("\nScanning common credential locations...\n")

	home := getHomeDir()
	if home == "" {
		return
	}

	paths := []string{
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, ".aws", "config"),
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".docker", "config.json"),
	}

	for _, path := range paths {

		if _, err := os.Stat(path); err == nil {

			if strings.Contains(path, ".aws") {
				scanAWSFile(path, results)
				continue
			}

			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			content := strings.ToLower(string(data))

			if strings.Contains(content, "token") ||
				strings.Contains(content, "password") ||
				strings.Contains(content, "secret") {

				fmt.Printf("Potential secret in file: %s\n", path)

				*results = append(*results, SecretResult{
					Source:   "common file",
					File:     path,
					Variable: "N/A",
					Value:    "[REDACTED]",
				})
			}
		}
	}
}

// scan SSH private keys
func scanSSHKeys(results *[]SecretResult) {

	fmt.Println("\nScanning SSH directory...\n")

	home := getHomeDir()
	sshDir := filepath.Join(home, ".ssh")

	files, err := os.ReadDir(sshDir)
	if err != nil {
		return
	}

	for _, file := range files {

		path := filepath.Join(sshDir, file.Name())

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		content := string(data)

		if strings.Contains(content, "PRIVATE KEY") {

			fmt.Printf("Private key detected: %s\n", path)

			*results = append(*results, SecretResult{
				Source:   "ssh key",
				File:     path,
				Variable: file.Name(),
				Value:    "[PRIVATE KEY DETECTED]",
			})
		}
	}
}

// scan system for sensitive files
func scanSystemForSensitiveFiles(results *[]SecretResult) {

	fmt.Println("\nScanning system for sensitive files...\n")

	root := getHomeDir() // safer + faster than "/"

	targetExtensions := []string{
		".env",
		".yml",
		".yaml",
		".pem",
		".key",
	}

	skipDirs := []string{
		"/proc",
		"/sys",
		"/dev",
		"/run",
	}

	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {

		if err != nil {
			return nil
		}

		// skip noisy/system dirs
		for _, dir := range skipDirs {
			if strings.HasPrefix(path, dir) {
				return filepath.SkipDir
			}
		}

		if info.IsDir() {
			return nil
		}

		for _, ext := range targetExtensions {

			if strings.HasSuffix(strings.ToLower(info.Name()), ext) {

				fmt.Printf("Found file: %s\n", path)

				switch ext {

				case ".env":
					scanEnvFile(path, results)

				case ".yml", ".yaml":
					scanYAMLFile(path, results)

				case ".pem", ".key":
					scanKeyFile(path, results)
				}
			}
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

	scanEnvVars(&results)
	scanSystemForSensitiveFiles(&results)
	scanCommonCredentialFiles(&results)
	scanSSHKeys(&results)

	exportJSON(results)
}