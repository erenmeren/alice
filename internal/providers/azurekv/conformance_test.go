package azurekv

import (
	"context"
	"testing"

	"alice/internal/platform/clock"
	"alice/internal/providers"
	"alice/internal/providers/providertest"
	"alice/internal/testutil/fakekv"
)

// TestConformanceAgainstTheFake runs the provider contract suite (spec §6.5 item 5) against the real
// provider wired to the fake Azure service, with every secret the run can touch as a needle.
func TestConformanceAgainstTheFake(t *testing.T) {
	s := fakekv.Start(t, fakekv.Options{})
	ver := s.AddCertificate("web-cert", fakekv.CertOptions{CommonName: "www.example.test", Exportable: true})
	p := testProvider(s)
	open := func(ctx context.Context) (providers.Session, error) {
		return p.Open(ctx, target(), &idSource{id: secretIdentity(s)}, providers.Env{Clock: clock.Real{}})
	}
	// Issue a token first: the harness reads the needle when it is built, and an empty one is skipped (D9).
	sess, err := open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()
	secrets := []string{s.Secret(), string(s.SecretValue("web-cert", ver)), s.LastAccessToken()}
	if secrets[2] == "" {
		t.Fatal("no access token was issued: the token needle would be empty")
	}

	providertest.CheckProvider(t, p)
	providertest.CheckSession(t, providertest.SessionHarness{Capabilities: p.Capabilities(), Open: open, Secrets: secrets})

	// The suite reads no secret value (an empty request is refused): read one, so that the value is
	// really at risk of showing up in the result or the error, and look for it everywhere.
	sess, err = open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sec, rerr := sess.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
	if rerr != nil || string(sec.Value.Bytes()) != string(s.SecretValue("web-cert", ver)) {
		t.Fatalf("the secret was not read: %v", rerr)
	}
	providertest.CheckNoSecrets(t, secrets, sec, rerr)
	sec.Zero()
	s.DisableVersion("web-cert", ver)
	_, derr := sess.ReadCertificateSecret(context.Background(), providers.SecretRequest{Name: "web-cert", Version: ver})
	if derr == nil {
		t.Fatal("a disabled version was read")
	}
	providertest.CheckNoSecrets(t, secrets, derr)
	s.EnableVersion("web-cert", ver)
	_ = sess.Close()

	// The suite cannot call ImportCertificate (it changes the vault): once here, with the same needles.
	pfx, _ := testPFX(t, "ecdsa256")
	sess, err = open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	res, ierr := sess.ImportCertificate(context.Background(), importReq("conformance-import", pfx, "ecdsa", 256), nil)
	providertest.CheckImportResult(t, res, ierr)
	if res.Outcome != providers.ImportCreated {
		t.Fatalf("import: %s %v", res.Outcome, ierr)
	}
	providertest.CheckNoSecrets(t, append(secrets, string(pfx), s.LastAccessToken()), res, ierr)
}
