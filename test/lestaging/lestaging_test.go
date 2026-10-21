//go:build lestaging

package lestaging

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// TestLetsEncryptStaging is the acceptance run against the real staging service (make le-staging). It skips when
// the ALICE_LE_* variables are not set; see docs/dev/le-staging-acceptance.md.
func TestLetsEncryptStaging(t *testing.T) {
	cfg, err := FromEnv(os.Getenv)
	var skip *SkipError
	if errors.As(err, &skip) {
		t.Skip(skip.Error())
	}
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(cfg, os.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	budget := 30 * time.Minute
	if cfg.OrderTimeout > 0 {
		budget = 3*cfg.OrderTimeout + 10*time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	if rep := r.Run(ctx); !rep.OK() {
		t.Fatal(rep.Summary())
	}
}
