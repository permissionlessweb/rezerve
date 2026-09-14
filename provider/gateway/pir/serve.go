package pir

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/akash-network/provider/pirgate"
)

const defaultServeImage = "python:3.12-alpine"

func leaseContainerName(leaseID string) string {
	var b strings.Builder
	b.WriteString("pir-lease-")
	for _, c := range leaseID {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

// ServeLease docker-runs a lightweight HTTP server for this lease.
// Fail-closed: PIR mode allocate (32-byte ask+bid hex, live cw-pir-commit
// {matches:true} when PIR_COMMIT_MATCH_URL is set) must pass before spawn.
func ServeLease(leaseID, bearer, image string, hostPort int) (string, int, error) {
	if !pirgate.PirAllocationAllowed() {
		return "", 0, fmt.Errorf("allocate denied (commit / zap1 gate)")
	}
	if err := AcceptBid(leaseID, bearer); err != nil {
		return "", 0, err
	}
	if image == "" {
		image = os.Getenv("PIR_SERVE_IMAGE")
	}
	if image == "" {
		image = defaultServeImage
	}
	if hostPort <= 0 {
		hostPort = 18765
	}
	name := leaseContainerName(leaseID)
	_ = exec.Command("docker", "rm", "-f", name).Run()
	args := []string{
		"run", "-d",
		"--name", name,
		"-p", fmt.Sprintf("%d:8080", hostPort),
		"--label", "pir.lease=" + leaseID,
		"--label", "pir.role=re-zerve-serve",
		image,
		"python", "-m", "http.server", "8080",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	id := strings.TrimSpace(string(out))
	if err != nil {
		return "", 0, fmt.Errorf("docker run: %w (%s)", err, id)
	}
	bookMu.Lock()
	m := loadBook()
	rec := m[leaseID]
	rec.Bearer = stringsLower(bearer)
	rec.Open = true
	rec.Container = id
	rec.HostPort = hostPort
	rec.Name = name
	m[leaseID] = rec
	_ = saveBook(m)
	bookMu.Unlock()
	if err := waitLeaseServing(name, hostPort); err != nil {
		_ = exec.Command("docker", "rm", "-f", name).Run()
		return "", 0, err
	}
	return id, hostPort, nil
}

// waitLeaseServing is true when the lease process answers HTTP 200.
// Prefer docker exec into the container (works from an ict sidecar that only
// has the daemon socket). Host-port GET is a fallback for the provider binary
// running on the same host as the published port.
func waitLeaseServing(name string, hostPort int) error {
	py := "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8080/', timeout=2); raise SystemExit(0 if r.status==200 else r.status)"
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "exec", name, "python", "-c", py).CombinedOutput()
		if err == nil {
			return nil
		}
		last = fmt.Errorf("exec: %s", strings.TrimSpace(string(out)))
		if hostPort > 0 {
			url := fmt.Sprintf("http://127.0.0.1:%d/", hostPort)
			res, herr := http.Get(url)
			if herr == nil {
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if res.StatusCode == 200 {
					return nil
				}
				last = fmt.Errorf("host status %d", res.StatusCode)
			} else {
				last = herr
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("lease container %s not serving HTTP: %v", name, last)
}

// StopServe removes the lease container and closes access.
func StopServe(leaseID string) error {
	name := leaseContainerName(leaseID)
	bookMu.Lock()
	m := loadBook()
	if rec, ok := m[leaseID]; ok && rec.Name != "" {
		name = rec.Name
	}
	bookMu.Unlock()
	_ = exec.Command("docker", "rm", "-f", name).Run()
	return CloseLease(leaseID)
}

// ContainerRunning is true if docker reports the lease container running.
func ContainerRunning(leaseID string) bool {
	name := leaseContainerName(leaseID)
	st, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(st)) == "true"
}
