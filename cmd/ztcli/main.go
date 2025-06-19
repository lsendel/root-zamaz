// Zero Trust CLI - Developer tool for MVP Zero Trust Auth system management
// Provides comprehensive commands for authentication testing, user management,
// token operations, and system administration.
//
// Example usage:
//   ztcli auth login user@example.com
//   ztcli user create --email user@example.com --role admin
//   ztcli token validate <token>
//   ztcli system health
//   ztcli dev generate-key
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"mvp.local/pkg/sdk/go"
)

var (
	cfgFile     string
	baseURL     string
	apiKey      string
	outputFormat string
	verbose     bool
	client      *sdk.Client
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ztcli",
	Short: "Zero Trust CLI - Developer tool for MVP Zero Trust Auth system",
	Long: `Zero Trust CLI is a comprehensive developer tool for managing and testing
the MVP Zero Trust Authentication system.

Features:
- User authentication and management
- Token validation and introspection
- System health monitoring
- Development utilities
- Configuration management
- Code generation tools

Example usage:
  ztcli auth login user@example.com
  ztcli user list --role admin
  ztcli token validate <token>
  ztcli system status
  ztcli dev generate-client --lang go`,
	PersistentPreRun: initializeClient,
}

// authCmd represents the auth command group
var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Authentication operations",
	Long:  "Commands for user authentication, login, logout, and token management.",
}

// userCmd represents the user command group
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User management operations",
	Long:  "Commands for creating, updating, deleting, and listing users.",
}

// tokenCmd represents the token command group
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token operations",
	Long:  "Commands for token validation, introspection, and management.",
}

// systemCmd represents the system command group
var systemCmd = &cobra.Command{
	Use:   "system",
	Short: "System administration",
	Long:  "Commands for system health, status, and administration.",
}

// devCmd represents the development utilities command group
var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "Development utilities",
	Long:  "Commands for development tasks like code generation and testing.",
}

// Auth commands
var loginCmd = &cobra.Command{
	Use:   "login [email]",
	Short: "Authenticate user and obtain tokens",
	Args:  cobra.ExactArgs(1),
	Run:   runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout current session",
	Run:   runLogout,
}

var refreshCmd = &cobra.Command{
	Use:   "refresh [refresh_token]",
	Short: "Refresh access token",
	Args:  cobra.ExactArgs(1),
	Run:   runRefresh,
}

// Token commands
var validateCmd = &cobra.Command{
	Use:   "validate [token]",
	Short: "Validate an access token",
	Args:  cobra.ExactArgs(1),
	Run:   runValidate,
}

var introspectCmd = &cobra.Command{
	Use:   "introspect [token]",
	Short: "Get detailed token information",
	Args:  cobra.ExactArgs(1),
	Run:   runIntrospect,
}

// User commands
var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	Run:   runUserList,
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user",
	Run:   runUserCreate,
}

var userShowCmd = &cobra.Command{
	Use:   "show [user_id]",
	Short: "Show user details",
	Args:  cobra.ExactArgs(1),
	Run:   runUserShow,
}

var userUpdateCmd = &cobra.Command{
	Use:   "update [user_id]",
	Short: "Update user details",
	Args:  cobra.ExactArgs(1),
	Run:   runUserUpdate,
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete [user_id]",
	Short: "Delete a user",
	Args:  cobra.ExactArgs(1),
	Run:   runUserDelete,
}

// System commands
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check system health",
	Run:   runHealth,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show system status",
	Run:   runStatus,
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show current configuration",
	Run:   runConfig,
}

// Dev commands
var generateKeyCmd = &cobra.Command{
	Use:   "generate-key",
	Short: "Generate API key",
	Run:   runGenerateKey,
}

var generateClientCmd = &cobra.Command{
	Use:   "generate-client",
	Short: "Generate SDK client code",
	Run:   runGenerateClient,
}

var testConnectionCmd = &cobra.Command{
	Use:   "test-connection",
	Short: "Test connection to Zero Trust Auth service",
	Run:   runTestConnection,
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ztcli.yaml)")
	rootCmd.PersistentFlags().StringVar(&baseURL, "url", "", "Zero Trust Auth service URL")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "API key for authentication")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "output format (table, json, yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Auth command flags
	loginCmd.Flags().String("password", "", "password for authentication")
	loginCmd.Flags().String("mfa", "", "MFA code")
	loginCmd.Flags().Bool("remember", false, "remember login")

	logoutCmd.Flags().String("token", "", "access token to logout")
	logoutCmd.Flags().Bool("everywhere", false, "logout from all sessions")

	// Token command flags
	validateCmd.Flags().StringSlice("scopes", []string{}, "required scopes")
	validateCmd.Flags().String("audience", "", "required audience")

	// User command flags
	userListCmd.Flags().String("role", "", "filter by role")
	userListCmd.Flags().String("status", "", "filter by status (active, inactive)")
	userListCmd.Flags().Int("limit", 50, "maximum number of users to return")
	userListCmd.Flags().Int("offset", 0, "offset for pagination")

	userCreateCmd.Flags().String("email", "", "user email (required)")
	userCreateCmd.Flags().String("first-name", "", "user first name")
	userCreateCmd.Flags().String("last-name", "", "user last name")
	userCreateCmd.Flags().String("password", "", "user password")
	userCreateCmd.Flags().StringSlice("roles", []string{}, "user roles")
	userCreateCmd.Flags().Bool("active", true, "user active status")
	userCreateCmd.Flags().Bool("verified", false, "user verified status")
	userCreateCmd.MarkFlagRequired("email")

	userUpdateCmd.Flags().String("email", "", "user email")
	userUpdateCmd.Flags().String("first-name", "", "user first name")
	userUpdateCmd.Flags().String("last-name", "", "user last name")
	userUpdateCmd.Flags().StringSlice("roles", []string{}, "user roles")
	userUpdateCmd.Flags().Bool("active", true, "user active status")
	userUpdateCmd.Flags().Bool("verified", false, "user verified status")

	// Dev command flags
	generateClientCmd.Flags().String("lang", "go", "target language (go, javascript, python)")
	generateClientCmd.Flags().String("output-dir", "./sdk", "output directory")
	generateClientCmd.Flags().String("package", "", "package name")

	// Add subcommands
	authCmd.AddCommand(loginCmd, logoutCmd, refreshCmd)
	tokenCmd.AddCommand(validateCmd, introspectCmd)
	userCmd.AddCommand(userListCmd, userCreateCmd, userShowCmd, userUpdateCmd, userDeleteCmd)
	systemCmd.AddCommand(healthCmd, statusCmd, configCmd)
	devCmd.AddCommand(generateKeyCmd, generateClientCmd, testConnectionCmd)

	rootCmd.AddCommand(authCmd, tokenCmd, userCmd, systemCmd, devCmd)
}

// initConfig reads in config file and ENV variables if set
func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".ztcli")
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("ZTCLI")

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	// Set defaults from config
	if baseURL == "" {
		baseURL = viper.GetString("base_url")
	}
	if apiKey == "" {
		apiKey = viper.GetString("api_key")
	}
}

// initializeClient initializes the SDK client
func initializeClient(cmd *cobra.Command, args []string) {
	if baseURL == "" {
		baseURL = "http://localhost:8080" // Default for development
	}
	if apiKey == "" {
		apiKey = "dev-api-key" // Default for development
	}

	var err error
	client, err = sdk.NewClient(sdk.Config{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Debug:   verbose,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing client: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Auth command implementations
func runLogin(cmd *cobra.Command, args []string) {
	email := args[0]
	password, _ := cmd.Flags().GetString("password")
	mfa, _ := cmd.Flags().GetString("mfa")
	remember, _ := cmd.Flags().GetBool("remember")

	if password == "" {
		fmt.Print("Password: ")
		fmt.Scanln(&password)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Authenticate(ctx, sdk.AuthenticationRequest{
		Email:    email,
		Password: password,
		MFA:      mfa,
		Remember: remember,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
		os.Exit(1)
	}

	if resp.RequiresMFA {
		fmt.Printf("MFA required. Challenge: %s\n", resp.MFAChallenge)
		fmt.Printf("Partial token: %s\n", resp.PartialToken)
		return
	}

	printOutput(resp)
	fmt.Printf("\n✅ Authentication successful!\n")
	fmt.Printf("Access Token: %s\n", resp.AccessToken)
	fmt.Printf("Expires At: %s\n", resp.ExpiresAt.Format(time.RFC3339))
}

func runLogout(cmd *cobra.Command, args []string) {
	token, _ := cmd.Flags().GetString("token")
	everywhere, _ := cmd.Flags().GetBool("everywhere")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := client.Logout(ctx, sdk.LogoutRequest{
		Token:      token,
		Everywhere: everywhere,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logout failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Logout successful!")
}

func runRefresh(cmd *cobra.Command, args []string) {
	refreshToken := args[0]

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.RefreshToken(ctx, sdk.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Token refresh failed: %v\n", err)
		os.Exit(1)
	}

	printOutput(resp)
	fmt.Printf("\n✅ Token refreshed successfully!\n")
}

// Token command implementations
func runValidate(cmd *cobra.Command, args []string) {
	token := args[0]
	scopes, _ := cmd.Flags().GetStringSlice("scopes")
	audience, _ := cmd.Flags().GetString("audience")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.ValidateToken(ctx, sdk.TokenValidationRequest{
		Token:          token,
		RequiredScopes: scopes,
		Audience:       audience,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Token validation failed: %v\n", err)
		os.Exit(1)
	}

	printOutput(resp)
	
	if resp.Valid {
		fmt.Printf("\n✅ Token is valid!\n")
	} else {
		fmt.Printf("\n❌ Token is invalid!\n")
		os.Exit(1)
	}
}

func runIntrospect(cmd *cobra.Command, args []string) {
	// For now, introspect is the same as validate with full details
	runValidate(cmd, args)
}

// User command implementations
func runUserList(cmd *cobra.Command, args []string) {
	fmt.Println("📋 User list functionality not yet implemented")
	fmt.Println("This would connect to the user management API")
}

func runUserCreate(cmd *cobra.Command, args []string) {
	email, _ := cmd.Flags().GetString("email")
	firstName, _ := cmd.Flags().GetString("first-name")
	lastName, _ := cmd.Flags().GetString("last-name")
	password, _ := cmd.Flags().GetString("password")
	roles, _ := cmd.Flags().GetStringSlice("roles")
	active, _ := cmd.Flags().GetBool("active")
	verified, _ := cmd.Flags().GetBool("verified")

	fmt.Printf("📝 Creating user: %s\n", email)
	fmt.Printf("Name: %s %s\n", firstName, lastName)
	fmt.Printf("Password provided: %t\n", password != "")
	fmt.Printf("Roles: %v\n", roles)
	fmt.Printf("Active: %t, Verified: %t\n", active, verified)
	fmt.Println("🚧 User creation functionality not yet implemented")
}

func runUserShow(cmd *cobra.Command, args []string) {
	userID := args[0]
	fmt.Printf("👤 Showing user: %s\n", userID)
	fmt.Println("🚧 User show functionality not yet implemented")
}

func runUserUpdate(cmd *cobra.Command, args []string) {
	userID := args[0]
	fmt.Printf("✏️ Updating user: %s\n", userID)
	fmt.Println("🚧 User update functionality not yet implemented")
}

func runUserDelete(cmd *cobra.Command, args []string) {
	userID := args[0]
	fmt.Printf("🗑️ Deleting user: %s\n", userID)
	fmt.Println("🚧 User deletion functionality not yet implemented")
}

// System command implementations
func runHealth(cmd *cobra.Command, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := client.HealthCheck(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Health check failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ System is healthy!")
}

func runStatus(cmd *cobra.Command, args []string) {
	fmt.Println("📊 System Status:")
	fmt.Printf("Base URL: %s\n", baseURL)
	fmt.Printf("API Key: %s\n", maskAPIKey(apiKey))
	
	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.HealthCheck(ctx)
	if err != nil {
		fmt.Printf("Connection: ❌ Failed (%v)\n", err)
	} else {
		fmt.Printf("Connection: ✅ Successful\n")
	}
}

func runConfig(cmd *cobra.Command, args []string) {
	cfg := client.GetConfig()
	printOutput(cfg)
}

// Dev command implementations
func runGenerateKey(cmd *cobra.Command, args []string) {
	utils := sdk.NewUtils()
	key, err := utils.Token.GenerateState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🔑 Generated API Key: %s\n", key)
	fmt.Println("💡 Store this key securely and use it for API authentication")
}

func runGenerateClient(cmd *cobra.Command, args []string) {
	lang, _ := cmd.Flags().GetString("lang")
	outputDir, _ := cmd.Flags().GetString("output-dir")
	packageName, _ := cmd.Flags().GetString("package")

	fmt.Printf("🔧 Generating %s SDK client...\n", lang)
	fmt.Printf("Output directory: %s\n", outputDir)
	if packageName != "" {
		fmt.Printf("Package name: %s\n", packageName)
	}
	
	fmt.Println("🚧 Code generation functionality not yet implemented")
	fmt.Println("This would generate SDK client code in the specified language")
}

func runTestConnection(cmd *cobra.Command, args []string) {
	fmt.Printf("🔗 Testing connection to %s...\n", baseURL)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	err := client.HealthCheck(ctx)
	duration := time.Since(start)

	if err != nil {
		fmt.Printf("❌ Connection failed after %v: %v\n", duration, err)
		os.Exit(1)
	}

	fmt.Printf("✅ Connection successful! Response time: %v\n", duration)
}

// Utility functions
func printOutput(data interface{}) {
	switch outputFormat {
	case "json":
		jsonData, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(jsonData))
	case "yaml":
		// For now, use JSON format for YAML
		jsonData, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(jsonData))
	default:
		// Table format would require more complex formatting
		jsonData, _ := json.MarshalIndent(data, "", "  ")
		fmt.Println(string(jsonData))
	}
}

func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}