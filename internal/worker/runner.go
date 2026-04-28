package worker

import (
	"context"
	"os"
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/altship-hq/safeclone/internal/report"
	"github.com/altship-hq/safeclone/internal/scanner"
)

// Runner executes scan jobs inside Docker sandboxes.
type Runner struct {
	docker *client.Client
}

// NewRunner creates a Runner using the Docker daemon from environment.
func NewRunner() (*Runner, error) {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	return &Runner{docker: c}, nil
}

// Run clones a repo in a sandbox, runs all scanners concurrently, and returns the report.
func (r *Runner) Run(ctx context.Context, url string) (*report.Report, error) {
	tmpDir, err := os.MkdirTemp("", "safeclone-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := r.cloneInSandbox(ctx, url, tmpDir); err != nil {
		return nil, err
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		rep     report.Report
		lastErr error
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		secrets, err := scanner.ScanSecrets(ctx, tmpDir)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			lastErr = err
			return
		}
		rep.Secrets = secrets
	}()

	go func() {
		defer wg.Done()
		vulns, err := scanner.ScanDependencies(tmpDir)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			lastErr = err
			return
		}
		rep.Vulns = vulns
	}()

	go func() {
		defer wg.Done()
		scripts := scanner.ScanScripts(tmpDir)
		mu.Lock()
		defer mu.Unlock()
		rep.Scripts = scripts
	}()

	wg.Wait()

	if lastErr != nil {
		return nil, lastErr
	}

	rep.Calculate()
	return &rep, nil
}

func (r *Runner) cloneInSandbox(ctx context.Context, url, tmpDir string) error {
	resp, err := r.docker.ContainerCreate(ctx,
		&container.Config{
			Image: "safeclone-scanner",
			Cmd:   []string{"git", "clone", "--depth=1", url, "/repo"},
		},
		&container.HostConfig{
			Mounts: []mount.Mount{{
				Type:   mount.TypeBind,
				Source: tmpDir,
				Target: "/repo",
			}},
			Resources: container.Resources{
				Memory:   512 * 1024 * 1024,
				NanoCPUs: 500_000_000,
			},
			NetworkMode: "host",
		},
		nil, nil, "",
	)
	if err != nil {
		return err
	}
	defer r.docker.ContainerRemove(ctx, resp.ID, container.RemoveOptions{Force: true})

	if err := r.docker.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return err
	}

	statusCh, errCh := r.docker.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
	case status := <-statusCh:
		if status.StatusCode != 0 {
			return &exitError{code: int(status.StatusCode)}
		}
	}
	return nil
}

type exitError struct{ code int }

func (e *exitError) Error() string {
	return "container exited with non-zero status"
}
