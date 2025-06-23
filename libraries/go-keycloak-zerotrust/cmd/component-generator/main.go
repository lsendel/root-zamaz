// Component Generator - Creates Go components following 2025 best practices
// This tool generates complete Go projects with proper structure, dependencies,
// and configuration following Maven-style component definitions.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// ComponentDefinition represents a component configuration
type ComponentDefinition struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name        string    `yaml:"name"`
	Version     string    `yaml:"version"`
	Description string    `yaml:"description"`
	Author      string    `yaml:"author"`
	Created     time.Time `yaml:"created"`
	Updated     time.Time `yaml:"updated"`
}

type Spec struct {
	Type         string       `yaml:"type"`
	Module       Module       `yaml:"module"`
	Dependencies Dependencies `yaml:"dependencies"`
	Build        Build        `yaml:"build"`
	Runtime      Runtime      `yaml:"runtime"`
	Security     Security     `yaml:"security"`
	Testing      Testing      `yaml:"testing"`
	Documentation Documentation `yaml:"documentation"`
	Deployment   Deployment   `yaml:"deployment"`
	Observability Observability `yaml:"observability"`
	Lifecycle    Lifecycle    `yaml:"lifecycle"`
	Quality      Quality      `yaml:"quality"`
}

type Module struct {
	Name      string `yaml:"name"`
	Path      string `yaml:"path"`
	Version   string `yaml:"version"`
	GoVersion string `yaml:"goVersion"`
}

type Dependencies struct {
	Required []Dependency `yaml:"required"`
	Optional []Dependency `yaml:"optional"`
}

type Dependency struct {
	Name      string `yaml:"name"`
	Version   string `yaml:"version"`
	Type      string `yaml:"type"`
	Condition string `yaml:"condition,omitempty"`
}

type Build struct {
	Tags []string          `yaml:"tags"`
	Env  map[string]string `yaml:"env"`
	CGO  CGO               `yaml:"cgo"`
}

type CGO struct {
	Enabled bool     `yaml:"enabled"`
	Flags   []string `yaml:"flags,omitempty"`
}

type Runtime struct {
	Environment []EnvVar  `yaml:"environment"`
	Resources   Resources `yaml:"resources"`
	Health      Health    `yaml:"health"`
}

type EnvVar struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Required    bool   `yaml:"required"`
	Default     string `yaml:"default"`
	Type        string `yaml:"type"`
}

type Resources struct {
	CPU    string `yaml:"cpu"`
	Memory string `yaml:"memory"`
}

type Health struct {
	Endpoint string `yaml:"endpoint"`
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
}

type Security struct {
	Permissions     []string        `yaml:"permissions"`
	Scan            SecurityScan    `yaml:"scan"`
	Vulnerabilities Vulnerabilities `yaml:"vulnerabilities"`
}

type SecurityScan struct {
	Enabled bool     `yaml:"enabled"`
	Tools   []string `yaml:"tools"`
}

type Vulnerabilities struct {
	Policy string `yaml:"policy"`
}

type Testing struct {
	Unit        UnitTest        `yaml:"unit"`
	Integration IntegrationTest `yaml:"integration"`
	E2E         E2ETest         `yaml:"e2e"`
}

type UnitTest struct {
	Coverage Coverage `yaml:"coverage"`
	Timeout  string   `yaml:"timeout"`
}

type Coverage struct {
	Minimum int `yaml:"minimum"`
	Target  int `yaml:"target"`
}

type IntegrationTest struct {
	Enabled      bool     `yaml:"enabled"`
	Dependencies []string `yaml:"dependencies"`
	Timeout      string   `yaml:"timeout"`
}

type E2ETest struct {
	Enabled     bool   `yaml:"enabled"`
	Environment string `yaml:"environment"`
	Timeout     string `yaml:"timeout"`
}

type Documentation struct {
	API       APIDoc       `yaml:"api"`
	User      UserDoc      `yaml:"user"`
	Developer DeveloperDoc `yaml:"developer"`
}

type APIDoc struct {
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

type UserDoc struct {
	Readme   string `yaml:"readme"`
	Examples string `yaml:"examples"`
}

type DeveloperDoc struct {
	Architecture  string `yaml:"architecture"`
	Contributing  string `yaml:"contributing"`
}

type Deployment struct {
	Container   Container   `yaml:"container"`
	Kubernetes  Kubernetes  `yaml:"kubernetes"`
	ServiceMesh ServiceMesh `yaml:"serviceMesh"`
}

type Container struct {
	Registry string `yaml:"registry"`
	Image    string `yaml:"image"`
	Tag      string `yaml:"tag"`
}

type Kubernetes struct {
	Namespace string `yaml:"namespace"`
	Resources string `yaml:"resources"`
}

type ServiceMesh struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"`
}

type Observability struct {
	Metrics Metrics `yaml:"metrics"`
	Logging Logging `yaml:"logging"`
	Tracing Tracing `yaml:"tracing"`
}

type Metrics struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	Format   string `yaml:"format"`
}

type Logging struct {
	Level       string `yaml:"level"`
	Format      string `yaml:"format"`
	Destination string `yaml:"destination"`
}

type Tracing struct {
	Enabled  bool   `yaml:"enabled"`
	Sampler  string `yaml:"sampler"`
	Endpoint string `yaml:"endpoint"`
}

type Lifecycle struct {
	PreBuild   []Hook `yaml:"preBuild"`
	PostBuild  []Hook `yaml:"postBuild"`
	PreDeploy  []Hook `yaml:"preDeploy"`
	PostDeploy []Hook `yaml:"postDeploy"`
}

type Hook struct {
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args"`
	WorkingDir string   `yaml:"workingDir"`
}

type Quality struct {
	Code        CodeQuality        `yaml:"code"`
	Security    SecurityQuality    `yaml:"security"`
	Performance PerformanceQuality `yaml:"performance"`
}

type CodeQuality struct {
	Linting    LintingConfig    `yaml:"linting"`
	Formatting FormattingConfig `yaml:"formatting"`
	Complexity ComplexityConfig `yaml:"complexity"`
}

type LintingConfig struct {
	Enabled bool     `yaml:"enabled"`
	Tools   []string `yaml:"tools"`
}

type FormattingConfig struct {
	Enabled bool   `yaml:"enabled"`
	Tool    string `yaml:"tool"`
}

type ComplexityConfig struct {
	Enabled   bool `yaml:"enabled"`
	Threshold int  `yaml:"threshold"`
}

type SecurityQuality struct {
	StaticAnalysis      StaticAnalysisConfig      `yaml:"staticAnalysis"`
	DependencyScanning  DependencyScanningConfig  `yaml:"dependencyScanning"`
}

type StaticAnalysisConfig struct {
	Enabled bool     `yaml:"enabled"`
	Tools   []string `yaml:"tools"`
}

type DependencyScanningConfig struct {
	Enabled bool   `yaml:"enabled"`
	Policy  string `yaml:"policy"`
}

type PerformanceQuality struct {
	Benchmarking BenchmarkingConfig `yaml:"benchmarking"`
	Profiling    ProfilingConfig    `yaml:"profiling"`
}

type BenchmarkingConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Threshold string `yaml:"threshold"`
}

type ProfilingConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"`
}

// TemplateData holds data for template rendering
type TemplateData struct {
	ComponentDefinition
	
	// Additional computed fields
	PackageName        string
	ModuleName         string
	ServiceName        string
	BinaryName         string
	CurrentTime        time.Time
	
	// Template-specific fields
	Imports         []Import
	Fields          []Field
	ConfigFields    []ConfigField
	Endpoints       []Endpoint
	Handlers        []Handler
	ReadinessChecks []ReadinessCheck
	
	// Build info
	CommitSHA string
	BuildTime string
	
	// Defaults
	DefaultPort         string
	DefaultHost         string
	DefaultReadTimeout  string
	DefaultWriteTimeout string
	DefaultLogLevel     string
	DefaultLogFormat    string
}

type Import struct {
	Alias string
	Path  string
}

type Field struct {
	Name string
	Type string
}

type ConfigField struct {
	Name    string
	Type    string
	EnvVar  string
	Default string
	Comment string
}

type Endpoint struct {
	Method  string
	Path    string
	Handler string
}

type Handler struct {
	Name            string
	Description     string
	ResponseMessage string
}

type ReadinessCheck struct {
	Name          string
	CheckFunction string
}

// Generator handles component generation
type Generator struct {
	logger        *slog.Logger
	templatesDir  string
	outputDir     string
}

func main() {
	var (
		configPath   = flag.String("config", "", "Path to component definition YAML file")
		outputDir    = flag.String("output", ".", "Output directory for generated component")
		templatesDir = flag.String("templates", "./templates", "Templates directory")
		verbose      = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Setup logging
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))

	if *configPath == "" {
		logger.Error("config path is required")
		flag.Usage()
		os.Exit(1)
	}

	generator := &Generator{
		logger:       logger,
		templatesDir: *templatesDir,
		outputDir:    *outputDir,
	}

	ctx := context.Background()
	if err := generator.Generate(ctx, *configPath); err != nil {
		logger.Error("generation failed", "error", err)
		os.Exit(1)
	}

	logger.Info("component generation completed successfully")
}

// Generate creates a new component from the definition
func (g *Generator) Generate(ctx context.Context, configPath string) error {
	g.logger.Info("starting component generation", "config", configPath)

	// Load component definition
	def, err := g.loadDefinition(configPath)
	if err != nil {
		return fmt.Errorf("failed to load definition: %w", err)
	}

	// Prepare template data
	data := g.prepareTemplateData(def)

	// Create output directory structure
	if err := g.createDirectoryStructure(data); err != nil {
		return fmt.Errorf("failed to create directory structure: %w", err)
	}

	// Generate files from templates
	if err := g.generateFiles(data); err != nil {
		return fmt.Errorf("failed to generate files: %w", err)
	}

	g.logger.Info("component generated successfully", "output", g.outputDir)
	return nil
}

// loadDefinition loads and parses the component definition
func (g *Generator) loadDefinition(path string) (*ComponentDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var def ComponentDefinition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	return &def, nil
}

// prepareTemplateData prepares data for template rendering
func (g *Generator) prepareTemplateData(def *ComponentDefinition) *TemplateData {
	data := &TemplateData{
		ComponentDefinition: *def,
		CurrentTime:         time.Now(),
		CommitSHA:          os.Getenv("COMMIT_SHA"),
		BuildTime:          time.Now().Format(time.RFC3339),
		
		// Computed fields
		PackageName: strings.ReplaceAll(strings.ToLower(def.Metadata.Name), "-", ""),
		ModuleName:  def.Spec.Module.Name,
		ServiceName: def.Metadata.Name,
		BinaryName:  def.Metadata.Name,
		
		// Defaults
		DefaultPort:         "8080",
		DefaultHost:         "0.0.0.0",
		DefaultReadTimeout:  "10s",
		DefaultWriteTimeout: "10s",
		DefaultLogLevel:     "info",
		DefaultLogFormat:    "json",
	}

	// Add default imports
	data.Imports = []Import{
		{Path: "context"},
		{Path: "encoding/json"},
		{Path: "errors"},
		{Path: "fmt"},
		{Path: "log/slog"},
		{Path: "net/http"},
		{Path: "os"},
		{Path: "os/signal"},
		{Path: "syscall"},
		{Path: "time"},
		{Path: "github.com/caarlos0/env/v9"},
	}

	// Add default endpoints
	data.Endpoints = []Endpoint{
		{Method: "GET", Path: "/api/v1/example", Handler: "handleExample"},
	}

	// Add default handlers
	data.Handlers = []Handler{
		{
			Name:            "handleExample",
			Description:     "example API endpoint",
			ResponseMessage: "Example response from " + def.Metadata.Name,
		},
	}

	return data
}

// createDirectoryStructure creates the necessary directories
func (g *Generator) createDirectoryStructure(data *TemplateData) error {
	dirs := []string{
		g.outputDir,
		filepath.Join(g.outputDir, "cmd", "server"),
		filepath.Join(g.outputDir, "internal"),
		filepath.Join(g.outputDir, "pkg"),
		filepath.Join(g.outputDir, "api"),
		filepath.Join(g.outputDir, "web"),
		filepath.Join(g.outputDir, "configs"),
		filepath.Join(g.outputDir, "scripts"),
		filepath.Join(g.outputDir, "deployments"),
		filepath.Join(g.outputDir, "test"),
		filepath.Join(g.outputDir, "docs"),
		filepath.Join(g.outputDir, ".github", "workflows"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// generateFiles generates files from templates
func (g *Generator) generateFiles(data *TemplateData) error {
	files := map[string]string{
		"go.mod":                    "go.mod.tmpl",
		"cmd/server/main.go":       "main.go.tmpl",
		"Dockerfile":               "dockerfile.tmpl",
	}

	for outputPath, templateName := range files {
		if err := g.generateFile(data, outputPath, templateName); err != nil {
			return fmt.Errorf("failed to generate %s: %w", outputPath, err)
		}
	}

	// Generate static files
	if err := g.generateStaticFiles(data); err != nil {
		return fmt.Errorf("failed to generate static files: %w", err)
	}

	return nil
}

// generateFile generates a single file from template
func (g *Generator) generateFile(data *TemplateData, outputPath, templateName string) error {
	templatePath := filepath.Join(g.templatesDir, templateName)
	
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	outputFile := filepath.Join(g.outputDir, outputPath)
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	g.logger.Debug("generated file", "path", outputFile)
	return nil
}

// generateStaticFiles generates non-template files
func (g *Generator) generateStaticFiles(data *TemplateData) error {
	// Generate README.md
	readmeContent := fmt.Sprintf(`# %s

%s

## Quick Start

### Prerequisites

- Go %s or later
- Docker
- Docker Compose

### Installation

1. Clone the repository
2. Run setup:
   `, data.Metadata.Name, data.Metadata.Description, data.Spec.Module.GoVersion)

	readmeContent += "```bash\nmake setup\nmake start\n```\n\n"
	readmeContent += "### Usage\n\n"
	readmeContent += "```bash\n# Health check\ncurl http://localhost:8080/health\n\n"
	readmeContent += "# API endpoint\ncurl http://localhost:8080/api/v1/example\n```\n"

	readmePath := filepath.Join(g.outputDir, "README.md")
	if err := os.WriteFile(readmePath, []byte(readmeContent), 0644); err != nil {
		return fmt.Errorf("failed to write README.md: %w", err)
	}

	// Generate .gitignore
	gitignoreContent := `# Binaries
*.exe
*.exe~
*.dll
*.so
*.dylib
/tmp/
dist/

# Test binary
*.test

# Coverage
*.out
coverage.html

# Go workspace
go.work

# Environment files
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
`

	gitignorePath := filepath.Join(g.outputDir, ".gitignore")
	if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
		return fmt.Errorf("failed to write .gitignore: %w", err)
	}

	// Generate component.yaml
	componentYAML, err := yaml.Marshal(data.ComponentDefinition)
	if err != nil {
		return fmt.Errorf("failed to marshal component definition: %w", err)
	}

	componentPath := filepath.Join(g.outputDir, "component.yaml")
	if err := os.WriteFile(componentPath, componentYAML, 0644); err != nil {
		return fmt.Errorf("failed to write component.yaml: %w", err)
	}

	return nil
}