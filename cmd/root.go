package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cloudflare/cloudflare-go"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

var (
	portFlag   int
	domainFlag string
	debugFlag  bool
	Version    = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "cftunn [PORT] [DOMAIN]",
	Short: "Expose your local service to the internet via Cloudflare Tunnel",
	Args:  cobra.RangeArgs(0, 2),
	Run:   run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Version = Version
	rootCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "Local port to tunnel to")
	rootCmd.Flags().StringVarP(&domainFlag, "domain", "d", "", "Domain to expose (e.g. dev.example.com)")
	rootCmd.Flags().BoolVarP(&debugFlag, "debug", "D", false, "Enable debug output for troubleshooting")
}

func debugLog(format string, args ...interface{}) {
	if debugFlag {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

func run(cmd *cobra.Command, args []string) {
	if len(args) > 0 {
		p, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Printf("Error parsing port: %v\n", err)
			os.Exit(1)
		}
		portFlag = p
	}
	if len(args) > 1 {
		domainFlag = args[1]
	}

	if portFlag == 0 || domainFlag == "" {
		fmt.Println("Usage: cftunn [PORT] [DOMAIN]")
		os.Exit(1)
	}

	debugLog("Checking for cloudflared in PATH...")
	cloudflaredPath, err := exec.LookPath("cloudflared")
	if err != nil {
		debugLog("cloudflared not found: %v", err)
		fmt.Println("Error: 'cloudflared' is not installed or not in PATH.")
		fmt.Println("Please install it: brew install cloudflared (on macOS) or see https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation")
		os.Exit(1)
	}
	debugLog("Found cloudflared at: %s", cloudflaredPath)

	// Check for API Token
	debugLog("Checking for CLOUDFLARE_API_TOKEN environment variable...")
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		debugLog("CLOUDFLARE_API_TOKEN found, using API mode")
		runAPIMode(cmd, args)
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
			runWrapperMode(cmd, args)
			return
		}
		debugLog("cert.pem not found: %v", err)
	} else {
		debugLog("Could not determine home directory: %v", err)
	}

	fmt.Println("Error: No authentication method found.")
	fmt.Println("Option 1 (Recommended): Login with cloudflared")
	fmt.Println("  Run: cloudflared tunnel login")
	fmt.Println("\nOption 2: Use an API Token")
	fmt.Println("  Export CLOUDFLARE_API_TOKEN environment variable.")
	os.Exit(1)
}

func runWrapperMode(cmd *cobra.Command, args []string) {
	fmt.Println("Using 'cloudflared' credentials (cert.pem found)...")

	tunnelName := fmt.Sprintf("cftunn-%s", strings.ReplaceAll(domainFlag, ".", "-"))
	debugLog("Generated tunnel name: %s", tunnelName)
	var token string

	// 1. Create Tunnel
	// Try to create.
	fmt.Printf("Ensuring tunnel '%s' exists...\n", tunnelName)
	debugLog("Attempting to create tunnel...")
	if err := execCloudflaredSilent("tunnel", "create", tunnelName); err != nil {
		// Creation failed, likely exists.
		// Try to fetch token to reuse it
		debugLog("Tunnel creation failed (may already exist), attempting to fetch token...")
		fmt.Println("Tunnel exists, trying to fetch token...")
		debugLog("Executing: cloudflared tunnel token %s", tunnelName)
		out, err := exec.Command("cloudflared", "tunnel", "token", tunnelName).Output()
		if err == nil {
			token = strings.TrimSpace(string(out))
			debugLog("Token retrieved successfully (length: %d)", len(token))
			fmt.Printf("Successfully retrieved token for existing tunnel '%s'.\n", tunnelName)
		} else {
			// Could not get token, must recreate
			debugLog("Token retrieval failed: %v", err)
			fmt.Printf("Could not get token (err: %v), recreating tunnel...\n", err)
			debugLog("Deleting existing tunnel...")
			if err := execCloudflared("tunnel", "delete", tunnelName); err != nil {
				debugLog("Delete failed (ignoring): %v", err)
				// Ignore delete error
			}
			debugLog("Creating new tunnel...")
			if err := execCloudflared("tunnel", "create", tunnelName); err != nil {
				debugLog("Tunnel creation failed: %v", err)
				fmt.Printf("Error creating tunnel: %v\n", err)
				os.Exit(1)
			}
			debugLog("Tunnel created successfully")
		}
	} else {
		debugLog("Tunnel created successfully")
	}

	// 2. Route DNS
	fmt.Printf("Routing DNS for %s...\n", domainFlag)
	debugLog("Routing DNS: tunnel=%s, domain=%s", tunnelName, domainFlag)
	if err := execCloudflaredSilent("tunnel", "route", "dns", tunnelName, domainFlag); err != nil {
		// Failed, likely exists.
		debugLog("DNS routing failed, record may already exist")
		fmt.Printf("Warning: DNS record for %s might already exist.\n", domainFlag)
		prompt := promptui.Prompt{
			Label:     "Do you want to overwrite it",
			IsConfirm: true,
		}
		if _, err := prompt.Run(); err != nil {
			debugLog("User aborted DNS overwrite")
			fmt.Println("Aborted.")
			os.Exit(0)
		}

		// Overwrite
		debugLog("User confirmed overwrite, forcing DNS route...")
		if err := execCloudflared("tunnel", "route", "dns", "-f", tunnelName, domainFlag); err != nil {
			debugLog("DNS routing with force failed: %v", err)
			fmt.Printf("Error routing DNS: %v\n", err)
			os.Exit(1)
		}
	}
	debugLog("DNS routing completed")
	fmt.Println("DNS routed.")

	// 3. Run
	fmt.Printf("Starting tunnel to localhost:%d...\n", portFlag)
	fmt.Printf("Your site should be available at https://%s shortly.\n", domainFlag)

	var c *exec.Cmd
	if token != "" {
		// Run with token
		debugLog("Starting tunnel with token (length: %d)", len(token))
		c = exec.Command("cloudflared", "tunnel", "run", "--url", fmt.Sprintf("localhost:%d", portFlag), "--token", token)
	} else {
		// Run with name (uses local credentials file)
		debugLog("Starting tunnel with name: %s", tunnelName)
		c = exec.Command("cloudflared", "tunnel", "run", "--url", fmt.Sprintf("localhost:%d", portFlag), tunnelName)
	}
	debugLog("Tunnel command: cloudflared tunnel run --url localhost:%d %s", portFlag, func() string { if token != "" { return "--token <redacted>" }; return tunnelName }())

	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	if err := c.Start(); err != nil {
		fmt.Printf("Error starting cloudflared: %v\n", err)
		os.Exit(1)
	}

	go func() {
		<-sigs
		fmt.Println("\nStopping tunnel...")
		c.Process.Signal(syscall.SIGINT)
	}()

	if err := c.Wait(); err != nil {
		// Check if it's a signal exit
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					return
				}
			}
		}
		fmt.Printf("Tunnel exited with error: %v\n", err)
	}
}

func execCloudflared(args ...string) error {
	cmd := exec.Command("cloudflared", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func execCloudflaredSilent(args ...string) error {
	debugLog("Executing: cloudflared %s", strings.Join(args, " "))
	cmd := exec.Command("cloudflared", args...)
	if debugFlag {
		output, err := cmd.CombinedOutput()
		if err != nil {
			debugLog("Command failed: %v", err)
			debugLog("Output: %s", string(output))
		} else {
			debugLog("Command succeeded")
		}
		return err
	}
	return cmd.Run()
}

func runAPIMode(cmd *cobra.Command, args []string) {
	apiKey := os.Getenv("CLOUDFLARE_API_TOKEN")
	debugLog("API token length: %d", len(apiKey))

	debugLog("Creating Cloudflare API client...")
	api, err := cloudflare.NewWithAPIToken(apiKey)
	if err != nil {
		debugLog("Failed to create Cloudflare client: %v", err)
		fmt.Printf("Error creating Cloudflare client: %v\n", err)
		os.Exit(1)
	}
	debugLog("Cloudflare API client created successfully")

	ctx := context.Background()

	debugLog("Looking up zone for domain: %s", domainFlag)
	zoneID, zoneName, err := findZone(ctx, api, domainFlag)
	if err != nil {
		debugLog("Zone lookup failed: %v", err)
		fmt.Printf("Error finding zone for %s: %v\n", domainFlag, err)
		os.Exit(1)
	}
	debugLog("Found zone: name=%s, id=%s", zoneName, zoneID)
	fmt.Printf("Found zone: %s (%s)\n", zoneName, zoneID)

	fmt.Println("Checking DNS records...")
	debugLog("Listing CNAME records for: %s", domainFlag)
	rc := cloudflare.ZoneIdentifier(zoneID)
	records, _, err := api.ListDNSRecords(ctx, rc, cloudflare.ListDNSRecordsParams{
		Name: domainFlag,
		Type: "CNAME",
	})
	if err != nil {
		debugLog("Failed to list DNS records: %v", err)
		fmt.Printf("Error listing DNS records: %v\n", err)
		os.Exit(1)
	}
	debugLog("Found %d existing CNAME records", len(records))

	var existingRecordID string
	if len(records) > 0 {
		record := records[0]
		debugLog("Existing record: id=%s, content=%s", record.ID, record.Content)
		fmt.Printf("Warning: A CNAME record for %s already exists pointing to %s.\n", domainFlag, record.Content)

		prompt := promptui.Prompt{
			Label:     "Do you want to overwrite it",
			IsConfirm: true,
		}

		_, err := prompt.Run()
		if err != nil {
			debugLog("User aborted DNS overwrite")
			fmt.Println("Aborted.")
			os.Exit(0)
		}
		existingRecordID = record.ID
		debugLog("User confirmed overwrite for record: %s", existingRecordID)
	}

	debugLog("Fetching account ID for zone: %s", zoneID)
	accountID, err := getAccountID(ctx, api, zoneID)
	if err != nil {
		debugLog("Failed to get account ID: %v", err)
		fmt.Printf("Error getting Account ID: %v\n", err)
		os.Exit(1)
	}
	debugLog("Account ID: %s", accountID)

	tunnelName := fmt.Sprintf("cftunn-%s", strings.ReplaceAll(domainFlag, ".", "-"))
	debugLog("Generated tunnel name: %s", tunnelName)
	fmt.Printf("Ensuring tunnel '%s' exists...\n", tunnelName)

	debugLog("Listing existing tunnels with name: %s", tunnelName)
	tunnels, _, err := api.ListTunnels(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.TunnelListParams{
		Name:      tunnelName,
		IsDeleted: cloudflare.BoolPtr(false),
	})
	if err != nil {
		debugLog("Failed to list tunnels: %v", err)
		fmt.Printf("Error listing tunnels: %v\n", err)
		os.Exit(1)
	}
	debugLog("Found %d existing tunnels with this name", len(tunnels))

	var tunnel cloudflare.Tunnel
	debugLog("Generating random tunnel secret...")
	tunnelSecret, err := generateRandomSecret()
	if err != nil {
		debugLog("Failed to generate secret: %v", err)
		fmt.Printf("Error generating secret: %v\n", err)
		os.Exit(1)
	}
	debugLog("Secret generated (length: %d)", len(tunnelSecret))

	if len(tunnels) > 0 {
		// Delete and Recreate to rotate secret (simplest path for API mode)
		oldTunnel := tunnels[0]
		debugLog("Found existing tunnel: id=%s, name=%s", oldTunnel.ID, oldTunnel.Name)
		fmt.Printf("Found existing tunnel %s, recreating to rotate secret...\n", oldTunnel.ID)
		debugLog("Deleting old tunnel: %s", oldTunnel.ID)
		err := api.DeleteTunnel(ctx, cloudflare.AccountIdentifier(accountID), oldTunnel.ID)
		if err != nil {
			debugLog("Failed to delete old tunnel: %v", err)
			fmt.Printf("Error deleting old tunnel: %v\n", err)
			os.Exit(1)
		}
		debugLog("Old tunnel deleted successfully")
	}

	// Create new tunnel
	debugLog("Creating new tunnel: name=%s, configSrc=cloudflare", tunnelName)
	t, err := api.CreateTunnel(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.TunnelCreateParams{
		Name:      tunnelName,
		Secret:    tunnelSecret,
		ConfigSrc: "cloudflare",
	})
	if err != nil {
		debugLog("Failed to create tunnel: %v", err)
		fmt.Printf("Error creating tunnel: %v\n", err)
		os.Exit(1)
	}
	tunnel = t
	debugLog("Tunnel created: id=%s", tunnel.ID)
	fmt.Printf("Created tunnel: %s\n", tunnel.ID)

	tunnelDomain := fmt.Sprintf("%s.cfargotunnel.com", tunnel.ID)
	debugLog("Tunnel domain: %s", tunnelDomain)

	if existingRecordID != "" {
		debugLog("Updating existing DNS record: id=%s, target=%s", existingRecordID, tunnelDomain)
		_, err := api.UpdateDNSRecord(ctx, rc, cloudflare.UpdateDNSRecordParams{
			ID:      existingRecordID,
			Type:    "CNAME",
			Name:    domainFlag,
			Content: tunnelDomain,
			Proxied: cloudflare.BoolPtr(true),
			TTL:     1,
		})
		if err != nil {
			debugLog("Failed to update DNS record: %v", err)
			fmt.Printf("Error updating DNS record: %v\n", err)
			os.Exit(1)
		}
		debugLog("DNS record updated successfully")
		fmt.Println("Updated CNAME record.")
	} else {
		debugLog("Creating new DNS record: name=%s, target=%s", domainFlag, tunnelDomain)
		_, err := api.CreateDNSRecord(ctx, rc, cloudflare.CreateDNSRecordParams{
			Type:    "CNAME",
			Name:    domainFlag,
			Content: tunnelDomain,
			Proxied: cloudflare.BoolPtr(true),
			TTL:     1,
		})
		if err != nil {
			debugLog("Failed to create DNS record: %v", err)
			fmt.Printf("Error creating DNS record: %v\n", err)
			os.Exit(1)
		}
		debugLog("DNS record created successfully")
		fmt.Println("Created CNAME record.")
	}

	debugLog("Generating tunnel token...")
	finalToken, err := makeToken(accountID, tunnel.ID, tunnelSecret)
	if err != nil {
		debugLog("Failed to create token: %v", err)
		fmt.Printf("Error creating token: %v\n", err)
		os.Exit(1)
	}
	debugLog("Token generated (length: %d)", len(finalToken))

	fmt.Printf("Starting tunnel to localhost:%d...\n", portFlag)
	fmt.Printf("Your site should be available at https://%s shortly.\n", domainFlag)

	// Run cloudflared with --url and --token
	debugLog("Executing: cloudflared tunnel run --url localhost:%d --token <redacted>", portFlag)
	cmdArgs := []string{"tunnel", "run", "--url", fmt.Sprintf("localhost:%d", portFlag), "--token", finalToken}
	c := exec.Command("cloudflared", cmdArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	
	if err := c.Start(); err != nil {
		fmt.Printf("Error starting cloudflared: %v\n", err)
		os.Exit(1)
	}
	
	go func() {
		<-sigs
		fmt.Println("\nStopping tunnel...")
		c.Process.Signal(syscall.SIGINT)
	}()
	
	if err := c.Wait(); err != nil {
		// Check if it's a signal exit
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					// Normal exit on signal
					return
				}
			}
		}
		fmt.Printf("Tunnel exited with error: %v\n", err)
	}
}

func findZone(ctx context.Context, api *cloudflare.API, domain string) (string, string, error) {
	parts := strings.Split(domain, ".")
	debugLog("Zone lookup: trying to find zone for %s (parts: %v)", domain, parts)
	for i := 0; i < len(parts)-1; i++ {
		zoneName := strings.Join(parts[i:], ".")
		debugLog("Zone lookup: trying %s", zoneName)
		id, err := api.ZoneIDByName(zoneName)
		if err == nil {
			debugLog("Zone lookup: found %s -> %s", zoneName, id)
			return id, zoneName, nil
		}
		debugLog("Zone lookup: %s not found (%v)", zoneName, err)
	}
	return "", "", fmt.Errorf("could not find zone for %s", domain)
}

func getAccountID(ctx context.Context, api *cloudflare.API, zoneID string) (string, error) {
	zone, err := api.ZoneDetails(ctx, zoneID)
	if err != nil {
		return "", err
	}
	return zone.Account.ID, nil
}

func generateRandomSecret() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func makeToken(account, tunnelID, secret string) (string, error) {
	data := map[string]string{
		"a": account,
		"t": tunnelID,
		"s": secret,
	}
	j, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(j), nil
}