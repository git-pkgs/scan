package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type result struct {
	Repository  string  `json:"repository"`
	Backend     string  `json:"backend"`
	Workers     int     `json:"workers"`
	Attribution bool    `json:"attribution"`
	Repetition  int     `json:"repetition"`
	WallMS      float64 `json:"wall_ms"`
	PeakMB      float64 `json:"peak_mb"`
	Findings    int     `json:"findings"`
	Summary     string  `json:"summary"`
}

func run(binary, repo string, workers int, attribute bool) (result, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "scan", repo, "--workers="+strconv.Itoa(workers), "--attribute="+strconv.FormatBool(attribute), "--format=json", "--exit-code=0")
	cmd.Env = append(os.Environ(), "GOMAXPROCS="+strconv.Itoa(workers))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	r := result{WallMS: float64(time.Since(start).Nanoseconds()) / 1e6, Summary: strings.TrimSpace(stderr.String())}
	if err != nil {
		return r, nil, fmt.Errorf("%s: %w: %s", binary, err, stderr.String())
	}
	if usage, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
		r.PeakMB = float64(usage.Maxrss) / 1e6
		if runtime.GOOS != "darwin" {
			r.PeakMB *= 1024
		}
	}
	var findings []string
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var finding map[string]any
		if err := json.Unmarshal(line, &finding); err != nil {
			return r, nil, err
		}
		encoded, err := json.Marshal(finding)
		if err != nil {
			return r, nil, err
		}
		findings = append(findings, string(encoded))
	}
	sort.Strings(findings)
	r.Findings = len(findings)
	return r, findings, nil
}

func repeatCount(raw string) (int, error) {
	if raw == "" {
		return 3, nil
	}
	count, err := strconv.Atoi(raw)
	if err != nil || count < 1 {
		return 0, fmt.Errorf("E2E_REPETITIONS must be a positive integer: %q", raw)
	}
	return count, nil
}

func main() {
	if len(os.Args) < 4 {
		panic("usage: e2e binary-directory results-file repository...")
	}
	repetitions, err := repeatCount(os.Getenv("E2E_REPETITIONS"))
	if err != nil {
		panic(err)
	}
	var results []result
	for _, repo := range os.Args[3:] {
		for _, attribute := range []bool{false, true} {
			if attribute && os.Getenv("E2E_DETECTION_ONLY") == "1" {
				continue
			}
			var expected []string
			initialized := false
			for _, workers := range []int{1, 4} {
				for repetition := 0; repetition < repetitions; repetition++ {
					backends := []string{"go", "native"}
					if repetition%2 == 1 {
						backends[0], backends[1] = backends[1], backends[0]
					}
					for _, backend := range backends {
						r, findings, err := run(filepath.Join(os.Args[1], "secrets-"+backend), repo, workers, attribute)
						if err != nil {
							panic(err)
						}
						r.Repository, r.Backend, r.Workers, r.Attribution, r.Repetition = repo, backend, workers, attribute, repetition
						if !initialized {
							expected, initialized = findings, true
						} else if !reflect.DeepEqual(expected, findings) {
							panic(fmt.Sprintf("findings differ for %s %s workers=%d attribute=%v: got=%d want=%d", repo, backend, workers, attribute, len(findings), len(expected)))
						}
						results = append(results, r)
						encoded, err := json.MarshalIndent(results, "", "  ")
						if err != nil {
							panic(err)
						}
						if err := os.WriteFile(os.Args[2], encoded, 0600); err != nil {
							panic(err)
						}
						fmt.Printf("%s %s workers=%d attribute=%v run=%d wall=%.1fms peak=%.1fMB findings=%d %s\n", filepath.Base(repo), backend, workers, attribute, repetition+1, r.WallMS, r.PeakMB, r.Findings, r.Summary)
					}
				}
			}
		}
	}
}
