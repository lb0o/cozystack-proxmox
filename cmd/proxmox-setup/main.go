package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// formatNestedMap formats a nested map into Terraform HCL format
func formatNestedMap(val map[string]interface{}, indent string) string {
	var parts []string
	for k, v := range val {
		parts = append(parts, fmt.Sprintf("%s%s = %s", indent, k, formatValue(v, indent+"  ")))
	}
	return fmt.Sprintf("{\n%s\n%s}", strings.Join(parts, "\n"), indent)
}

// getScriptDir resolves the directory where the source .go file lives
func getScriptDir() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("Could not determine current file path")
	}
	return filepath.Dir(filename)
}

// formatList formats a list into Terraform HCL format
func formatList(val []interface{}, indent string) string {
	if len(val) == 0 {
		return "[]"
	}

	var parts []string
	for _, item := range val {
		parts = append(parts, formatValue(item, indent+"  "))
	}
	return fmt.Sprintf("[\n%s%s\n%s]", indent, strings.Join(parts, ",\n"+indent), indent)
}

// formatValue formats a value into Terraform HCL format
func formatValue(v interface{}, indent string) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf(`"%s"`, val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int, int64, float64:
		return fmt.Sprintf("%v", val)
	case []interface{}:
		return formatList(val, indent)
	case map[string]interface{}:
		return formatNestedMap(val, indent+"  ")
	case nil:
		return "null"
	default:
		return `""`
	}
}

// extractFlattenedMap extracts values from a nested map with a prefix
func extractFlattenedMap(prefix string, data map[string]interface{}, output map[string]interface{}) {
	for k, v := range data {
		if nestedMap, ok := v.(map[string]interface{}); ok {
			if prefix == "" {
				extractFlattenedMap(k, nestedMap, output)
			} else {
				extractFlattenedMap(prefix+"_"+k, nestedMap, output)
			}
		} else {
			if prefix == "" {
				output[k] = v
			} else {
				output[prefix+"_"+k] = v
			}
		}
	}
}

func processYAML(yamlPath string) error {
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		return fmt.Errorf("file %s does not exist", yamlPath)
	}

	yamlFile, err := os.ReadFile(yamlPath)
	if err != nil {
		return fmt.Errorf("error reading YAML file: %v", err)
	}

	data := make(map[string]interface{})
	err = yaml.Unmarshal(yamlFile, &data)
	if err != nil {
		return fmt.Errorf("error parsing YAML: %v", err)
	}

	// Create a flattened map for all variables
	virtualEnvVars := make(map[string]interface{})

	// Process proxmox section (keep original keys)
	if proxmox, ok := data["proxmox"].(map[string]interface{}); ok {
		for k, v := range proxmox {
			virtualEnvVars[k] = v
		}
	}

	// Process provider section
	if provider, ok := data["provider"].(map[string]interface{}); ok {
		if proxmox, ok := provider["proxmox"].(map[string]interface{}); ok {
			for k, v := range proxmox {
				// Add provider_ prefix to avoid key conflicts
				virtualEnvVars["provider_"+k] = v
			}
		}
	}

	// Process terraform section
	if terraform, ok := data["terraform"].(map[string]interface{}); ok {
		extractFlattenedMap("terraform", terraform, virtualEnvVars)
	}

	// Process network section
	if network, ok := data["network"].(map[string]interface{}); ok {
		for k, v := range network {
			virtualEnvVars[k] = v
		}
	}

	// Process domain section
	if domain, ok := data["domain"].(map[string]interface{}); ok {
		if name, ok := domain["name"].(string); ok {
			virtualEnvVars["domain"] = name
		}
	}

	// Process VM section
	if vm, ok := data["vm"].(map[string]interface{}); ok {
		for k, v := range vm {
			virtualEnvVars[k] = v
		}
	}

	// Process talos section
	if talos, ok := data["talos"].(map[string]interface{}); ok {
		if std, ok := talos["talos_standard"].(map[string]interface{}); ok {
			for k, v := range std {
				virtualEnvVars["talos_"+k] = v
			}
		}
	}

	// Build output
	var output []string
	output = append(output, "# Generated from "+yamlPath)
	output = append(output, "virtual_environment = {")

	// Sort keys alphabetically for better readability
	sortedKeys := make([]string, 0, len(virtualEnvVars))
	for k := range virtualEnvVars {
		sortedKeys = append(sortedKeys, k)
	}

	for _, k := range sortedKeys {
		output = append(output, fmt.Sprintf("  %s = %s", k, formatValue(virtualEnvVars[k], "  ")))
	}

	output = append(output, "}")

	scriptDir := getScriptDir()
	outPath := filepath.Join(scriptDir, "../../terraform_talos/var.tfvars")
	err = os.WriteFile(outPath, []byte(strings.Join(output, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("error writing tfvars file: %v", err)
	}

	fmt.Printf("Conversion complete: %s created.\n", outPath)
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "vault" {
		vaultCommand()
		return
	}

	scriptDir := getScriptDir()
	yamlPath := filepath.Join(scriptDir, "../../templates/var.tfvars.yaml")
	if len(os.Args) > 1 {
		yamlPath = os.Args[1]
	}

	if err := processYAML(yamlPath); err != nil {
		log.Fatal(err)
	}
}
