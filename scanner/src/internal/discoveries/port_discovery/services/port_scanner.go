package services

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vulwall/scanners/internal/shared"
)

const (
	// ScanTimeout is the timeout for each port connection attempt
	ScanTimeout = 2 * time.Second
)

// PortResult represents the result of scanning a single port
type PortResult struct {
	Port   int
	Open   bool
	Banner string // Optional service banner if detected
	Error  error
}

// Scanner provides simple TCP port scanning functionality
type Scanner struct {
	timeout time.Duration
}

// NewScanner creates a new port scanner with the specified timeout
func NewScanner() *Scanner {
	return &Scanner{
		timeout: ScanTimeout,
	}
}

// ScanPort checks if a single port is open on the target IP
func (s *Scanner) ScanPort(ctx context.Context, ip string, port int) PortResult {
	result := PortResult{
		Port: port,
		Open: false,
	}

	// Reject private/reserved IPs to prevent SSRF against internal infrastructure.
	if isPrivate, err := shared.IsPrivateIP(ip); err != nil || isPrivate {
		if err != nil {
			result.Error = fmt.Errorf("ssrf-guard: invalid IP address %q: %w", ip, err)
		} else {
			result.Error = fmt.Errorf("ssrf-guard: refusing to scan private/reserved IP %q", ip)
		}
		return result
	}

	// Create a dialer with timeout
	dialer := net.Dialer{
		Timeout: s.timeout,
	}

	// Attempt TCP connection
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Error = err
		return result
	}
	defer conn.Close()

	// Port is open
	result.Open = true

	// Try to grab banner (optional, with short timeout)
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err == nil {
		buffer := make([]byte, 256)
		if n, err := conn.Read(buffer); err == nil && n > 0 {
			result.Banner = string(buffer[:n])
		}
	}

	return result
}

const maxConcurrentDials = 20

// ScanPorts scans multiple ports concurrently on the target IP
func (s *Scanner) ScanPorts(ctx context.Context, ip string, ports []int) []PortResult {
	results := make([]PortResult, 0, len(ports))
	resultsChan := make(chan PortResult, len(ports))
	sem := make(chan struct{}, maxConcurrentDials)

	var wg sync.WaitGroup

	// Scan each port concurrently, capped at maxConcurrentDials
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()

			// Check if context is cancelled
			select {
			case <-ctx.Done():
				resultsChan <- PortResult{Port: p, Open: false, Error: ctx.Err()}
				return
			default:
			}

			sem <- struct{}{}
			defer func() { <-sem }()

			result := s.ScanPort(ctx, ip, p)
			resultsChan <- result
		}(port)
	}

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

// ScanPortsFiltered scans ports and returns only open ports
func (s *Scanner) ScanPortsFiltered(ctx context.Context, ip string, ports []int) []PortResult {
	allResults := s.ScanPorts(ctx, ip, ports)

	openPorts := make([]PortResult, 0)
	for _, result := range allResults {
		if result.Open {
			openPorts = append(openPorts, result)
		}
	}

	return openPorts
}
