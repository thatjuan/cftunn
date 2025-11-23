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
	rootCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "Local port to tunnel to")
	rootCmd.Flags().StringVarP(&domainFlag, "domain", "d", "", "Domain to expose (e.g. dev.example.com)")
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

	if _, err := exec.LookPath("cloudflared"); err != nil {
		fmt.Println("Error: 'cloudflared' is not installed or not in PATH.")
		fmt.Println("Please install it: brew install cloudflared (on macOS) or see https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation")
		os.Exit(1)
	}

	// Check for API Token
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		runAPIMode(cmd, args)
		return
	}

	// Check for cloudflared cert.pem
	home, err := os.UserHomeDir()
	if err == nil {
		certPath := fmt.Sprintf("%s/.cloudflared/cert.pem", home)
		if _, err := os.Stat(certPath); err == nil {
			runWrapperMode(cmd, args)
			return
		}
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
	
	// 1. Create Tunnel
	// Try to create. If it fails, we assume it might exist.
	// We can't easily check existence without parsing 'list', so we'll try to delete first if create fails?
	// Or just try to delete blindly first? simpler to ensure clean state.
	// But deleting requires it to exist.
	// Let's try create, if fail, delete and create.
	
	fmt.Printf("Ensuring tunnel '%s' exists...\n", tunnelName)
	// We can use 'cloudflared tunnel list' to check, but parsing is annoying.
	// Let's try to create.
	if err := execCloudflaredSilent("tunnel", "create", tunnelName); err != nil {
		// Assume it exists, try to delete
		fmt.Printf("Tunnel might exist, recreating...\n")
		if err := execCloudflared("tunnel", "delete", tunnelName); err != nil {
			// If delete fails, maybe it didn't exist and create failed for another reason?
			// Or it belongs to another user?
			// Try create again just in case delete worked or was unneeded
		}
		if err := execCloudflared("tunnel", "create", tunnelName); err != nil {
			fmt.Printf("Error creating tunnel: %v\n", err)
			os.Exit(1)
		}
	}

	// 2. Route DNS
	fmt.Printf("Routing DNS for %s...\n", domainFlag)
	if err := execCloudflaredSilent("tunnel", "route", "dns", tunnelName, domainFlag); err != nil {
		// Failed, likely exists.
		fmt.Printf("Warning: DNS record for %s might already exist.\n", domainFlag)
		prompt := promptui.Prompt{
			Label:     "Do you want to overwrite it",
			IsConfirm: true,
		}
		if _, err := prompt.Run(); err != nil {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
		
		// Overwrite
		if err := execCloudflared("tunnel", "route", "dns", "-f", tunnelName, domainFlag); err != nil {
			fmt.Printf("Error routing DNS: %v\n", err)
			os.Exit(1)
		}
	}
	fmt.Println("DNS routed.")

	// 3. Run
	fmt.Printf("Starting tunnel to localhost:%d...\n", portFlag)
	fmt.Printf("Your site should be available at https://%s shortly.\n", domainFlag)

	// We don't need --token because cloudflared finds the cred file for the named tunnel automatically
	c := exec.Command("cloudflared", "tunnel", "run", "--url", fmt.Sprintf("localhost:%d", portFlag), tunnelName)
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
	cmd := exec.Command("cloudflared", args...)
	return cmd.Run()
}

func runAPIMode(cmd *cobra.Command, args []string) {
	apiKey := os.Getenv("CLOUDFLARE_API_TOKEN")
	
	api, err := cloudflare.NewWithAPIToken(apiKey)
	if err != nil {
		fmt.Printf("Error creating Cloudflare client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	zoneID, zoneName, err := findZone(ctx, api, domainFlag)
	if err != nil {
		fmt.Printf("Error finding zone for %s: %v\n", domainFlag, err)
		os.Exit(1)
	}
	fmt.Printf("Found zone: %s (%s)\n", zoneName, zoneID)

	fmt.Println("Checking DNS records...")
	rc := cloudflare.ZoneIdentifier(zoneID)
	records, _, err := api.ListDNSRecords(ctx, rc, cloudflare.ListDNSRecordsParams{
		Name: domainFlag,
		Type: "CNAME",
	})
	if err != nil {
		fmt.Printf("Error listing DNS records: %v\n", err)
		os.Exit(1)
	}

	var existingRecordID string
	if len(records) > 0 {
		record := records[0]
		fmt.Printf("Warning: A CNAME record for %s already exists pointing to %s.\n", domainFlag, record.Content)
		
		prompt := promptui.Prompt{
			Label:     "Do you want to overwrite it",
			IsConfirm: true,
		}

		_, err := prompt.Run()
		if err != nil {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
		existingRecordID = record.ID
	}

	accountID, err := getAccountID(ctx, api, zoneID)
	if err != nil {
		fmt.Printf("Error getting Account ID: %v\n", err)
		os.Exit(1)
	}

	tunnelName := fmt.Sprintf("cftunn-%s", strings.ReplaceAll(domainFlag, ".", "-"))
	fmt.Printf("Ensuring tunnel '%s' exists...\n", tunnelName)

	tunnels, _, err := api.ListTunnels(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.TunnelListParams{
		Name: tunnelName,
		IsDeleted: cloudflare.BoolPtr(false),
	})
	if err != nil {
		fmt.Printf("Error listing tunnels: %v\n", err)
		os.Exit(1)
	}

	var tunnel cloudflare.Tunnel
	tunnelSecret, err := generateRandomSecret()
	if err != nil {
		fmt.Printf("Error generating secret: %v\n", err)
		os.Exit(1)
	}

	if len(tunnels) > 0 {
		// Delete and Recreate to rotate secret
		oldTunnel := tunnels[0]
		fmt.Printf("Found existing tunnel %s, recreating to rotate secret...\n", oldTunnel.ID)
		err := api.DeleteTunnel(ctx, cloudflare.AccountIdentifier(accountID), oldTunnel.ID)
		if err != nil {
			fmt.Printf("Error deleting old tunnel: %v\n", err)
			os.Exit(1)
		}
	}

	// Create new tunnel
	t, err := api.CreateTunnel(ctx, cloudflare.AccountIdentifier(accountID), cloudflare.TunnelCreateParams{
		Name:      tunnelName,
		Secret:    tunnelSecret,
		ConfigSrc: "cloudflare", 
	})
	if err != nil {
		fmt.Printf("Error creating tunnel: %v\n", err)
		os.Exit(1)
	}
	tunnel = t
	fmt.Printf("Created tunnel: %s\n", tunnel.ID)

	tunnelDomain := fmt.Sprintf("%s.cfargotunnel.com", tunnel.ID)
	
	if existingRecordID != "" {
		_, err := api.UpdateDNSRecord(ctx, rc, cloudflare.UpdateDNSRecordParams{
			ID:      existingRecordID,
			Type:    "CNAME",
			Name:    domainFlag,
			Content: tunnelDomain,
			Proxied: cloudflare.BoolPtr(true),
			TTL:     1,
		})
		if err != nil {
			fmt.Printf("Error updating DNS record: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Updated CNAME record.")
	} else {
		_, err := api.CreateDNSRecord(ctx, rc, cloudflare.CreateDNSRecordParams{
			Type:    "CNAME",
			Name:    domainFlag,
			Content: tunnelDomain,
			Proxied: cloudflare.BoolPtr(true),
			TTL:     1,
		})
		if err != nil {
			fmt.Printf("Error creating DNS record: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Created CNAME record.")
	}

	finalToken, err := makeToken(accountID, tunnel.ID, tunnelSecret)
	if err != nil {
		fmt.Printf("Error creating token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Starting tunnel to localhost:%d...\n", portFlag)
	fmt.Printf("Your site should be available at https://%s shortly.\n", domainFlag)
	
	// Run cloudflared with --url and --token
	// This creates a quick-tunnel style connection but anchored to our named tunnel.
	// Actually, --url creates a quick tunnel if no tunnel is specified?
	// If --token is provided, --url defines the origin service but uses the token's tunnel identity!
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
		<-		sigs
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
	for i := 0; i < len(parts)-1; i++ {
		zoneName := strings.Join(parts[i:], ".")
		id, err := api.ZoneIDByName(zoneName)
		if err == nil {
			return id, zoneName, nil
		}
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