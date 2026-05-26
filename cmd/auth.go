package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/spf13/cobra"
)

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication",
	Long:  "Commands for managing and inspecting Cloudflare authentication.",
}

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Display current authentication context",
	Long:  "Show information about the currently authenticated Cloudflare account.",
	Run:   runWhoami,
}

var (
	createTokenName    string
	createTokenZone    string
	createTokenAccount string
)

var createTokenCmd = &cobra.Command{
	Use:   "create-token",
	Short: "Mint a cftunn-scoped API token using a bootstrap token",
	Long: `Mint a new API token scoped to cftunn's needs (Cloudflare Tunnel:Edit,
DNS:Edit, Zone:Read) using the token in CLOUDFLARE_API_TOKEN as a bootstrap.

The bootstrap token must have the "API Tokens Write" permission, which is
granted by the dashboard "Create Additional Tokens" template. The freshly
minted token's secret value is printed to stdout and shown only once.`,
	Run: runCreateToken,
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(whoamiCmd)
	authCmd.AddCommand(createTokenCmd)
	createTokenCmd.Flags().StringVar(&createTokenName, "name", "cftunn", "Name for the new token")
	createTokenCmd.Flags().StringVar(&createTokenZone, "zone", "", "Restrict zone scope to this zone name (default: all zones in account)")
	createTokenCmd.Flags().StringVar(&createTokenAccount, "account", "", "Account ID to scope the token to (default: first accessible account)")
}

func runWhoami(cmd *cobra.Command, args []string) {
	debugLog("Starting auth whoami...")

	// Check for API Token first
	debugLog("Checking for CLOUDFLARE_API_TOKEN environment variable...")
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if apiToken != "" {
		debugLog("CLOUDFLARE_API_TOKEN found, using API mode")
		runWhoamiAPIMode(apiToken)
		return
	}
	debugLog("CLOUDFLARE_API_TOKEN not set")

	// Check for cloudflared cert.pem
	debugLog("Checking for cloudflared credentials (cert.pem)...")
	home, err := os.UserHomeDir()
	if err == nil {
		certPath := fmt.Sprintf("%s/.cloudflared/cert.pem", home)
		debugLog("Looking for cert.pem at: %s", certPath)
		if _, err := os.Stat(certPath); err == nil {
			debugLog("cert.pem found, using wrapper mode")
			runWhoamiWrapperMode(certPath)
			return
		}
		debugLog("cert.pem not found: %v", err)
	} else {
		debugLog("Could not determine home directory: %v", err)
	}

	fmt.Println("Not authenticated.")
	fmt.Println()
	fmt.Println("To authenticate, choose one of the following options:")
	fmt.Println()
	fmt.Println("Option 1 (Recommended): Login with cloudflared")
	fmt.Println("  Run: cloudflared tunnel login")
	fmt.Println()
	fmt.Println("Option 2: Use an API Token")
	fmt.Println("  Export CLOUDFLARE_API_TOKEN environment variable.")
	os.Exit(1)
}

func runWhoamiAPIMode(apiToken string) {
	debugLog("Creating Cloudflare API client...")
	api, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		debugLog("Failed to create Cloudflare client: %v", err)
		fmt.Printf("Error creating Cloudflare client: %v\n", err)
		os.Exit(1)
	}
	debugLog("Cloudflare API client created successfully")

	ctx := context.Background()

	// Try to verify token and get user details
	debugLog("Verifying API token...")
	result, err := api.VerifyAPIToken(ctx)
	if err != nil {
		debugLog("Token verification failed: %v", err)
		fmt.Printf("Error: Invalid or expired API token: %v\n", err)
		os.Exit(1)
	}
	debugLog("Token verification result: status=%s", result.Status)

	if result.Status != "active" {
		fmt.Printf("Error: API token is not active (status: %s)\n", result.Status)
		os.Exit(1)
	}

	// Get account information by listing accounts
	debugLog("Fetching accounts...")
	accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
	if err != nil {
		debugLog("Failed to list accounts: %v", err)
		// Token might not have account:read permission, that's okay
		debugLog("Could not list accounts (permission may be missing): %v", err)
	}

	fmt.Println("Authentication: API Token")
	fmt.Println("Status: Active")
	fmt.Println()

	if len(accounts) > 0 {
		fmt.Println("Accounts:")
		for _, account := range accounts {
			fmt.Printf("  - %s (%s)\n", account.Name, account.ID)
		}
	} else {
		fmt.Println("Accounts: (none accessible or permission not granted)")
	}

	// Show token expiry if set
	if !result.ExpiresOn.IsZero() {
		fmt.Println()
		fmt.Printf("Token expires: %s\n", result.ExpiresOn.Format("2006-01-02 15:04:05 UTC"))
	}
}

func runWhoamiWrapperMode(certPath string) {
	debugLog("Using cloudflared credentials from: %s", certPath)

	// Check if cloudflared is available
	cloudflaredPath, err := exec.LookPath("cloudflared")
	if err != nil {
		debugLog("cloudflared not found: %v", err)
		fmt.Println("Error: 'cloudflared' is not installed or not in PATH.")
		fmt.Println("Please install it: brew install cloudflared (on macOS)")
		os.Exit(1)
	}
	debugLog("Found cloudflared at: %s", cloudflaredPath)

	// Use cloudflared tunnel info to get account details
	// First, try to list tunnels to verify authentication works
	debugLog("Executing: cloudflared tunnel list --output json")
	out, err := exec.Command("cloudflared", "tunnel", "list", "--output", "json").Output()
	if err != nil {
		debugLog("Failed to list tunnels: %v", err)
		// Try without json flag for older versions
		debugLog("Trying without JSON output...")
		out, err = exec.Command("cloudflared", "tunnel", "list").Output()
		if err != nil {
			debugLog("Failed to list tunnels: %v", err)
			fmt.Println("Error: Could not verify cloudflared authentication.")
			fmt.Printf("  %v\n", err)
			fmt.Println()
			fmt.Println("Your cert.pem may be expired. Try:")
			fmt.Println("  cloudflared tunnel login")
			os.Exit(1)
		}
		// Non-JSON output, just confirm auth works
		fmt.Println("Authentication: cloudflared (cert.pem)")
		fmt.Printf("Credentials: %s\n", certPath)
		fmt.Println("Status: Active")
		fmt.Println()

		// Count tunnels from text output
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		tunnelCount := 0
		if len(lines) > 1 { // First line is header
			tunnelCount = len(lines) - 1
		}
		fmt.Printf("Tunnels: %d found\n", tunnelCount)
		return
	}

	// Parse JSON output
	var tunnels []struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	if err := json.Unmarshal(out, &tunnels); err != nil {
		debugLog("Failed to parse tunnel list JSON: %v", err)
		// Not a critical error, just show basic info
		fmt.Println("Authentication: cloudflared (cert.pem)")
		fmt.Printf("Credentials: %s\n", certPath)
		fmt.Println("Status: Active")
		return
	}

	debugLog("Found %d tunnels", len(tunnels))

	fmt.Println("Authentication: cloudflared (cert.pem)")
	fmt.Printf("Credentials: %s\n", certPath)
	fmt.Println("Status: Active")
	fmt.Println()
	fmt.Printf("Tunnels: %d found\n", len(tunnels))

	// Show cftunn-managed tunnels if any
	cftunnTunnels := []string{}
	for _, t := range tunnels {
		if strings.HasPrefix(t.Name, "cftunn-") {
			cftunnTunnels = append(cftunnTunnels, t.Name)
		}
	}

	if len(cftunnTunnels) > 0 {
		fmt.Println()
		fmt.Println("cftunn-managed tunnels:")
		for _, name := range cftunnTunnels {
			fmt.Printf("  - %s\n", name)
		}
	}
}

func runCreateToken(cmd *cobra.Command, args []string) {
	bootstrap := os.Getenv("CLOUDFLARE_API_TOKEN")
	if bootstrap == "" {
		fmt.Println("Error: CLOUDFLARE_API_TOKEN is not set.")
		fmt.Println("Set it to a bootstrap token with the 'API Tokens Write' permission.")
		fmt.Println("Create one from the 'Create Additional Tokens' template at:")
		fmt.Println("  https://dash.cloudflare.com/profile/api-tokens")
		os.Exit(1)
	}

	api, err := cloudflare.NewWithAPIToken(bootstrap)
	if err != nil {
		fmt.Printf("Error creating Cloudflare client: %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()

	debugLog("Resolving account ID...")
	accountID := createTokenAccount
	if accountID == "" {
		accounts, _, err := api.Accounts(ctx, cloudflare.AccountsListParams{})
		if err != nil {
			fmt.Printf("Error listing accounts: %v\n", err)
			fmt.Println("The bootstrap token may lack 'Account:Read' — pass --account <id> explicitly.")
			os.Exit(1)
		}
		if len(accounts) == 0 {
			fmt.Println("Error: no accessible accounts. Pass --account <id> explicitly.")
			os.Exit(1)
		}
		accountID = accounts[0].ID
		debugLog("Using account: %s (%s)", accounts[0].Name, accountID)
	}

	var zoneResource string
	if createTokenZone != "" {
		debugLog("Looking up zone ID for: %s", createTokenZone)
		zoneID, err := api.ZoneIDByName(createTokenZone)
		if err != nil {
			fmt.Printf("Error looking up zone %q: %v\n", createTokenZone, err)
			os.Exit(1)
		}
		zoneResource = fmt.Sprintf("com.cloudflare.api.account.zone.%s", zoneID)
		debugLog("Pinning zone scope to: %s", zoneResource)
	} else {
		zoneResource = "com.cloudflare.api.account.zone.*"
		debugLog("Granting zone scope on all zones")
	}
	accountResource := fmt.Sprintf("com.cloudflare.api.account.%s", accountID)

	debugLog("Listing permission groups...")
	groups, err := api.ListAPITokensPermissionGroups(ctx)
	if err != nil {
		fmt.Printf("Error listing permission groups: %v\n", err)
		fmt.Println("The bootstrap token may lack 'API Tokens Read' — required to mint scoped tokens.")
		os.Exit(1)
	}
	debugLog("Loaded %d permission groups", len(groups))

	tunnelPG, err := findPermissionGroup(groups, "com.cloudflare.api.account", "Cloudflare Tunnel Write", "Cloudflare Tunnel")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	dnsPG, err := findPermissionGroup(groups, "com.cloudflare.api.account.zone", "DNS Write")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	zoneReadPG, err := findPermissionGroup(groups, "com.cloudflare.api.account.zone", "Zone Read")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	debugLog("Permission group IDs: tunnel=%s dns=%s zone-read=%s", tunnelPG.ID, dnsPG.ID, zoneReadPG.ID)

	token := cloudflare.APIToken{
		Name: createTokenName,
		Policies: []cloudflare.APITokenPolicies{
			{
				Effect:           "allow",
				Resources:        map[string]interface{}{accountResource: "*"},
				PermissionGroups: []cloudflare.APITokenPermissionGroups{{ID: tunnelPG.ID}},
			},
			{
				Effect:    "allow",
				Resources: map[string]interface{}{zoneResource: "*"},
				PermissionGroups: []cloudflare.APITokenPermissionGroups{
					{ID: dnsPG.ID},
					{ID: zoneReadPG.ID},
				},
			},
		},
	}

	debugLog("Creating token: name=%q", createTokenName)
	created, err := api.CreateAPIToken(ctx, token)
	if err != nil {
		fmt.Printf("Error creating token: %v\n", err)
		fmt.Println("The bootstrap token may lack 'API Tokens Write'.")
		os.Exit(1)
	}

	fmt.Printf("Created token %q (id: %s)\n", created.Name, created.ID)
	fmt.Println()
	fmt.Println("Token value (shown once — copy it now):")
	fmt.Println()
	fmt.Println(created.Value)
	fmt.Println()
	fmt.Println("Export it for cftunn:")
	fmt.Printf("  export CLOUDFLARE_API_TOKEN=%s\n", created.Value)
}

func findPermissionGroup(groups []cloudflare.APITokenPermissionGroups, scope string, names ...string) (cloudflare.APITokenPermissionGroups, error) {
	for _, want := range names {
		for _, g := range groups {
			if g.Name != want {
				continue
			}
			for _, s := range g.Scopes {
				if s == scope {
					return g, nil
				}
			}
		}
	}
	return cloudflare.APITokenPermissionGroups{}, fmt.Errorf("permission group not found for scope %q (tried names: %v)", scope, names)
}
