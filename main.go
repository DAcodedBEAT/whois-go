package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
)

const (
	defaultWhoisServer = "whois.iana.org"
	defaultWhoisPort   = 43
	maxBufferSize      = 32 * 1024 // Max buffer size for WHOIS response
)

// Options holds command-line options and defaults for the WHOIS client.
type Options struct {
	ShowRedirects bool
	Server        string
	Port          int
}

// WHOISResult represents the result of a WHOIS query, containing the response string and any associated error.
type WHOISResult struct {
	Response string
	Error    error
}

// recursiveWhoIsQuery follows WHOIS queries recursively to obtain the complete responses for each domain.
func recursiveWhoIsQuery(opts Options, domains []string) map[string]WHOISResult {
	responseMap := make(map[string]WHOISResult)

	for _, domain := range domains {
		result := performSingleWhoIsQuery(opts.Server, opts.Port, domain)
		responseMap[domain] = result
	}

	return responseMap
}

// performSingleWhoIsQuery performs a single WHOIS query for a given domain.
func performSingleWhoIsQuery(server string, port int, domain string) WHOISResult {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", server, port))
	if err != nil {
		return WHOISResult{"", fmt.Errorf("failed to connect to WHOIS server: %v", err)}
	}
	defer func(conn net.Conn) {
		connCloseErr := conn.Close()
		if connCloseErr != nil {
			slog.Error("could not close connection", "error", connCloseErr)
		}
	}(conn)

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return WHOISResult{"", fmt.Errorf("failed to send WHOIS query: %v", err)}
	}

	reader := bufio.NewReader(conn)
	var sb strings.Builder

	for {
		line, err := reader.ReadString('\n') // Read until newline
		if err != nil {
			break // EOF or read error
		}

		sb.WriteString(line)

		// Check for redirection
		trimmed := strings.TrimSpace(strings.ToLower(line))
		if strings.HasPrefix(trimmed, "whois server:") {
			redirect := strings.TrimSpace(line[len("whois server:"):])
			if redirect != "" && redirect != server {
				return performSingleWhoIsQuery(redirect, port, domain) // Recursive call for redirection
			}
		}

		if sb.Len() >= maxBufferSize {
			break
		}
	}

	return WHOISResult{sb.String(), nil}
}

func main() {
	opts := parseOptions()

	domains := flag.Args()

	// Setup slog with default handler
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if len(domains) == 0 {
		slog.Error("No domain provided")
		os.Exit(1)
	}

	result := recursiveWhoIsQuery(opts, domains)

	printResults(result)
}

// parseOptions parses command-line options and returns Options struct.
func parseOptions() Options {
	opts := Options{
		Server: defaultWhoisServer,
		Port:   defaultWhoisPort,
	}

	showRedirects := flag.Bool("i", false, "Show redirect results too")
	server := flag.String("h", opts.Server, "Server to query")
	port := flag.Int("p", opts.Port, "Port number to query")

	flag.Parse()

	opts.ShowRedirects = *showRedirects
	opts.Server = *server
	opts.Port = *port

	return opts
}

// printResults prints WHOIS query results.
func printResults(results map[string]WHOISResult) {
	erroredWhoIsLookupCount := 0
	for domain, whoisResp := range results {
		if err := whoisResp.Error; err != nil {
			slog.Error("Error querying WHOIS", "domain", domain, "error", err)
			erroredWhoIsLookupCount++
		}

		fmt.Printf("WHOIS response for %s:\n%s\n\n", domain, whoisResp.Response)
	}

	if erroredWhoIsLookupCount == len(results) {
		os.Exit(1)
	}
}
