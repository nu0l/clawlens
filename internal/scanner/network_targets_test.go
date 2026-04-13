package scanner

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestScanTargetNetworkDetectsOpenPort(t *testing.T) {
	dial := func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address == "192.168.1.5:18789" {
			return fakeConn{}, nil
		}
		return nil, errors.New("refused")
	}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	findings, err := ScanTargetNetwork([]string{"192.168.1.5"}, dial, client, nil)
	if err != nil {
		t.Fatalf("ScanTargetNetwork error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != Warning {
		t.Fatalf("expected Warning, got %v", findings[0].Severity)
	}
}

func TestScanTargetNetworkDetectsAuthRisk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("openclaw gateway"))
	}))
	defer srv.Close()

	host, portRaw, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	port, err := net.LookupPort("tcp", portRaw)
	if err != nil {
		t.Fatalf("LookupPort: %v", err)
	}

	client := srv.Client()
	client.Timeout = 2 * time.Second

	findings, err := scanTargetNetwork([]string{host}, port, net.DialTimeout, client, nil)
	if err != nil {
		t.Fatalf("scanTargetNetwork error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != Critical {
		t.Fatalf("expected Critical, got %v", findings[0].Severity)
	}
}
