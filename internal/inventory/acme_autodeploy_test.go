package inventory

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// acmePlanFixture is an ACME certificate with automatic deployment on, a current certificate issued two hours ago (valid
// for 60 days, complete chain), and three bound locations (automatic deployment on, bound 10 days ago) that serve an
// older certificate ending in 10 days.
type acmePlanFixture struct {
	sn      acmeDeploySnapshot
	cur     uuid.UUID
	a, b, c uuid.UUID
}

func newACMEPlanFixture() *acmePlanFixture {
	f := &acmePlanFixture{cur: uuid.New()}
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	slices.SortFunc(ids, func(x, y uuid.UUID) int { return strings.Compare(x.String(), y.String()) })
	f.a, f.b, f.c = ids[0], ids[1], ids[2]
	old := uuid.New()
	f.sn = acmeDeploySnapshot{now: planNow, gateOpen: true, autoDeploy: true, remaining: autoDeployBatch,
		current: &acmeDeployCert{id: f.cur, notBefore: planNow.Add(-3 * time.Hour), notAfter: planNow.Add(60 * 24 * time.Hour), chainComplete: true,
			issuedAt: planNow.Add(-2 * time.Hour)}}
	for _, id := range ids {
		f.sn.bindings = append(f.sn.bindings, acmeDeployBinding{location: id, autoDeploy: true, createdAt: planNow.Add(-10 * 24 * time.Hour),
			served: &old})
	}
	return f
}

func (f *acmePlanFixture) dep(loc uuid.UUID, ago time.Duration, status, code string, automatic bool) {
	d := acmeDeployment{location: loc, certificate: f.cur, automatic: automatic, done: status != "running", status: status, errorCode: code,
		createdAt: planNow.Add(-ago - time.Minute)}
	if d.done {
		d.finishedAt = tp(planNow.Add(-ago))
	}
	f.sn.deployments = append(f.sn.deployments, d)
}

func (f *acmePlanFixture) failed(loc uuid.UUID, ago time.Duration, code string) {
	f.dep(loc, ago, DeployStatusRolledBack, code, true)
}

func (f *acmePlanFixture) binding(loc uuid.UUID) *acmeDeployBinding {
	for i := range f.sn.bindings {
		if f.sn.bindings[i].location == loc {
			return &f.sn.bindings[i]
		}
	}
	return nil
}

func TestACMEAutoDeployPlanTable(t *testing.T) {
	all := func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.a, f.b, f.c} }
	none := func(*acmePlanFixture) []uuid.UUID { return nil }
	for _, tc := range []struct {
		name      string
		mutate    func(f *acmePlanFixture)
		deploy    func(f *acmePlanFixture) []uuid.UUID
		budget    int
		hold      string
		stop      int
		stopCode  string
		attention func(f *acmePlanFixture) []acmeAttention
	}{
		{name: "a new certificate goes to every bound location", deploy: all, budget: AutoDeployWave},
		{name: "nothing while the gate is closed", mutate: func(f *acmePlanFixture) { f.sn.gateOpen = false }, deploy: none},
		{name: "nothing with automatic deployment off", mutate: func(f *acmePlanFixture) { f.sn.autoDeploy = false }, deploy: none},
		{name: "nothing without a current certificate", mutate: func(f *acmePlanFixture) { f.sn.current = nil }, deploy: none},
		{name: "a binding with automatic deployment off is left out", mutate: func(f *acmePlanFixture) { f.binding(f.b).autoDeploy = false },
			deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.a, f.c} }, budget: AutoDeployWave},
		{name: "a location serving the current certificate is left out", mutate: func(f *acmePlanFixture) { f.binding(f.a).served = &f.cur },
			deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "a location that got it is left out", mutate: func(f *acmePlanFixture) { f.dep(f.a, time.Hour, DeployStatusSucceeded, "", true) },
			deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "a busy location is left out and an automatic one in flight uses the wave", mutate: func(f *acmePlanFixture) {
			f.sn.deployments = append(f.sn.deployments, acmeDeployment{location: f.a, certificate: uuid.New(), automatic: true, status: "running",
				createdAt: planNow})
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave - 1},
		{name: "the run's remaining batch bounds the budget", mutate: func(f *acmePlanFixture) { f.sn.remaining = 2 }, deploy: all, budget: 2},
		{name: "no batch left: nothing", mutate: func(f *acmePlanFixture) { f.sn.remaining = 0 }, deploy: none},
		{name: "a failed location waits an hour", mutate: func(f *acmePlanFixture) { f.failed(f.a, 59*time.Minute, "deployment.reload_failed") },
			deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave,
			attention: func(f *acmePlanFixture) []acmeAttention { return []acmeAttention{{f.a, "deployment.reload_failed"}} }},
		{name: "after an hour the retry comes after the fresh ones", mutate: func(f *acmePlanFixture) {
			f.failed(f.a, time.Hour, "deployment.reload_failed")
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c, f.a} }, budget: AutoDeployWave,
			attention: func(f *acmePlanFixture) []acmeAttention { return []acmeAttention{{f.a, "deployment.reload_failed"}} }},
		{name: "a person's failed deployment spaces the location too, but is no failure of the wave", mutate: func(f *acmePlanFixture) {
			f.dep(f.a, 10*time.Minute, DeployStatusFailed, "ssh.unreachable", false)
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "three failures stop the wave", mutate: func(f *acmePlanFixture) {
			f.failed(f.a, 3*time.Hour, "deployment.reload_failed")
			f.failed(f.b, 2*time.Hour, "deployment.config_test_failed")
			f.failed(f.c, time.Hour, "deployment.verify_failed")
		}, deploy: none, stop: 3, stopCode: "deployment.verify_failed",
			attention: func(f *acmePlanFixture) []acmeAttention {
				return []acmeAttention{{f.a, "deployment.reload_failed"}, {f.b, "deployment.config_test_failed"}, {f.c, "deployment.verify_failed"}}
			}},
		{name: "neutral reasons do not count", mutate: func(f *acmePlanFixture) {
			for _, l := range []uuid.UUID{f.a, f.b, f.c} {
				f.failed(l, 2*time.Hour, ReasonChainUnconfirmed)
			}
			f.failed(f.a, time.Hour, ReasonCertificateExpired)
		}, deploy: all, budget: AutoDeployWave},
		{name: "internal faults use a location's attempts up and stop the wave", mutate: func(f *acmePlanFixture) {
			for i := range 3 {
				f.failed(f.a, time.Duration(i+1)*time.Hour, ReasonInternal)
			}
		}, deploy: none, stop: 3, stopCode: ReasonInternal,
			attention: func(f *acmePlanFixture) []acmeAttention { return []acmeAttention{{f.a, ReasonInternal}} }},
		{name: "failures before the binding existed do not count", mutate: func(f *acmePlanFixture) {
			for i := range 3 {
				f.failed(f.a, time.Duration(11*24+i)*time.Hour, "deployment.reload_failed")
			}
		}, deploy: all, budget: AutoDeployWave},
		{name: "a stopped wave is left alone", mutate: func(f *acmePlanFixture) { f.sn.stopped = true }, deploy: none},
		{name: "an incomplete chain is held", mutate: func(f *acmePlanFixture) { f.sn.current.chainComplete = false }, deploy: none,
			hold: ACMEHoldChainIncomplete},
		{name: "a held certificate is left alone", mutate: func(f *acmePlanFixture) { f.sn.heldReason = ACMEHoldChainIncomplete }, deploy: none},
		{name: "released from the licence hold it is deployed", mutate: func(f *acmePlanFixture) {
			f.sn.heldReason, f.sn.released = ACMEHoldLicense, true
			f.sn.reopened = tp(planNow.Add(-time.Hour))
		}, deploy: all, budget: AutoDeployWave},
		{name: "a chain hold is not released", mutate: func(f *acmePlanFixture) {
			f.sn.heldReason, f.sn.released = ACMEHoldChainIncomplete, true
		}, deploy: none},
		{name: "issued before the gate reopened: held for the licence", mutate: func(f *acmePlanFixture) {
			f.sn.reopened = tp(planNow.Add(-time.Hour))
		}, deploy: none, hold: ACMEHoldLicense},
		{name: "issued at the reopening: held", mutate: func(f *acmePlanFixture) { f.sn.reopened = tp(f.sn.current.issuedAt) },
			deploy: none, hold: ACMEHoldLicense},
		{name: "bound after the reopening: not held", mutate: func(f *acmePlanFixture) {
			f.sn.reopened = tp(planNow.Add(-time.Hour))
			for i := range f.sn.bindings {
				f.sn.bindings[i].createdAt = planNow.Add(-time.Minute)
			}
		}, deploy: all, budget: AutoDeployWave},
		{name: "one location bound before the reopening: held", mutate: func(f *acmePlanFixture) {
			f.sn.reopened = tp(planNow.Add(-time.Hour))
			f.binding(f.a).createdAt = planNow.Add(-time.Minute)
			f.binding(f.b).createdAt = planNow.Add(-time.Minute)
		}, deploy: none, hold: ACMEHoldLicense},
		{name: "issued after the gate reopened: deployed", mutate: func(f *acmePlanFixture) { f.sn.reopened = tp(planNow.Add(-3 * time.Hour)) },
			deploy: all, budget: AutoDeployWave},
		{name: "a wave that began before the lock continues", mutate: func(f *acmePlanFixture) {
			f.sn.reopened = tp(planNow.Add(-time.Hour))
			f.dep(f.a, 2*time.Hour, DeployStatusSucceeded, "", true)
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "an expired certificate is left alone", mutate: func(f *acmePlanFixture) { f.sn.current.notAfter = planNow }, deploy: none},
		{name: "a certificate not yet valid is left alone", mutate: func(f *acmePlanFixture) { f.sn.current.notBefore = planNow.Add(time.Second) },
			deploy: none},
		{name: "nothing to deploy: no hold", mutate: func(f *acmePlanFixture) {
			f.sn.current.chainComplete = false
			for i := range f.sn.bindings {
				f.sn.bindings[i].served = &f.cur
			}
		}, deploy: none},
		{name: "an attention mark is cleared once the location got the certificate", mutate: func(f *acmePlanFixture) {
			f.binding(f.a).attentionCode = "deployment.reload_failed"
			f.failed(f.a, 3*time.Hour, "deployment.reload_failed")
			f.dep(f.a, time.Hour, DeployStatusSucceeded, "", true)
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave,
			attention: func(f *acmePlanFixture) []acmeAttention { return []acmeAttention{{f.a, ""}} }},
		{name: "an attention mark of an older certificate is cleared", mutate: func(f *acmePlanFixture) {
			f.binding(f.b).attentionCode = "deployment.reload_failed"
		}, deploy: all, budget: AutoDeployWave,
			attention: func(f *acmePlanFixture) []acmeAttention { return []acmeAttention{{f.b, ""}} }},
		{name: "a mark that is right is not written again", mutate: func(f *acmePlanFixture) {
			f.binding(f.a).attentionCode = "deployment.reload_failed"
			f.failed(f.a, 10*time.Minute, "deployment.reload_failed")
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.b, f.c} }, budget: AutoDeployWave},
		{name: "attention marks change while the wave is stopped too", mutate: func(f *acmePlanFixture) {
			f.sn.stopped = true
			f.failed(f.c, time.Hour, "deployment.verify_failed")
		}, deploy: none, attention: func(f *acmePlanFixture) []acmeAttention { return []acmeAttention{{f.c, "deployment.verify_failed"}} }},
		{name: "a location with three attempts is capped", mutate: func(f *acmePlanFixture) {
			f.failed(f.a, 5*time.Hour, ReasonInternal)
			f.failed(f.a, 4*time.Hour, ReasonInternal)
			f.failed(f.b, 3*time.Hour, "deployment.reload_failed")
			f.failed(f.b, 2*time.Hour, "deployment.reload_failed")
		}, deploy: func(f *acmePlanFixture) []uuid.UUID { return []uuid.UUID{f.c, f.a, f.b} }, budget: AutoDeployWave,
			attention: func(f *acmePlanFixture) []acmeAttention {
				return []acmeAttention{{f.a, ReasonInternal}, {f.b, "deployment.reload_failed"}}
			}},
		// R55: the service's policy forbids automatic deployment: the automatic bindings are marked, nothing is planned.
		{name: "a policy that forbids automatic deployment holds every automatic binding", mutate: func(f *acmePlanFixture) {
			f.sn.forbidden = true
			f.binding(f.b).autoDeploy = false
			f.binding(f.c).untrusted = true
			f.sn.current.chainComplete = false // would be held otherwise
		}, deploy: none, attention: func(f *acmePlanFixture) []acmeAttention {
			return []acmeAttention{{f.a, ReasonAutoDeployForbidden}, {f.c, ReasonAutoDeployForbidden}}
		}},
		{name: "a forbidden mark already set is not written again and nothing stops", mutate: func(f *acmePlanFixture) {
			f.sn.forbidden = true
			for _, l := range []uuid.UUID{f.a, f.b, f.c} {
				f.binding(l).attentionCode = ReasonAutoDeployForbidden
				f.failed(l, time.Hour, "deployment.reload_failed")
			}
		}, deploy: none},
		{name: "the policy allows it again: the marks clear and the wave resumes", mutate: func(f *acmePlanFixture) {
			for _, l := range []uuid.UUID{f.a, f.b, f.c} {
				f.binding(l).attentionCode = ReasonAutoDeployForbidden
			}
		}, deploy: all, budget: AutoDeployWave, attention: func(f *acmePlanFixture) []acmeAttention {
			return []acmeAttention{{f.a, ""}, {f.b, ""}, {f.c, ""}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newACMEPlanFixture()
			if tc.mutate != nil {
				tc.mutate(f)
			}
			p := planACMEAutoDeploy(f.sn)
			want := tc.deploy(f)
			if len(want) == 0 {
				assert.Empty(t, p.deploy)
			} else {
				assert.Equal(t, want, p.deploy)
				assert.Equal(t, tc.budget, p.budget)
			}
			assert.Equal(t, tc.hold, p.hold)
			if tc.hold != "" {
				assert.NotEmpty(t, p.candidate)
			}
			if tc.stop > 0 {
				if assert.NotNil(t, p.stop) {
					assert.Equal(t, tc.stop, p.stop.failed)
					assert.Equal(t, f.cur, p.stop.version)
					assert.Equal(t, tc.stopCode, p.stopCode)
				}
			} else {
				assert.Nil(t, p.stop)
			}
			var wantAttention []acmeAttention
			if tc.attention != nil {
				wantAttention = tc.attention(f)
			}
			assert.ElementsMatch(t, wantAttention, p.attention)
		})
	}
}

// insertCallers maps each function (or method) of the package's production files to the deploy helpers it calls, in
// source order.
func deployHelperCalls(t *testing.T) map[string][]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	out := map[string][]string{}
	helpers := map[string]bool{"insertDeployment": true, "readDeployCertificate": true, "lockDeployTargets": true, "checkDeployLocation": true}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		require.NoError(t, err)
		f, err := parser.ParseFile(fset, name, src, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var callee string
				switch f := call.Fun.(type) {
				case *ast.Ident:
					callee = f.Name
				case *ast.SelectorExpr:
					callee = f.Sel.Name
				}
				if helpers[callee] {
					out[fn.Name.Name] = append(out[fn.Name.Name], callee)
				}
				return true
			})
			// A function value that holds a helper (s.insertDeployment passed or stored) would escape the call check.
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					for _, arg := range call.Args {
						if sel, ok := arg.(*ast.SelectorExpr); ok && sel.Sel.Name == "insertDeployment" {
							out[fn.Name.Name] = append(out[fn.Name.Name], "insertDeployment(as a value)")
						}
					}
				}
				if as, ok := n.(*ast.AssignStmt); ok {
					for _, r := range as.Rhs {
						if sel, ok := r.(*ast.SelectorExpr); ok && sel.Sel.Name == "insertDeployment" {
							out[fn.Name.Name] = append(out[fn.Name.Name], "insertDeployment(as a value)")
						}
					}
				}
				return true
			})
		}
	}
	return out
}

// A2 / Review Focus 2: insertDeployment is called only by a person's RequestDeployment, the Key Vault "Deploy now"
// (RequestKVDeployment), the Key Vault planner (planBinding) and prepareACMEDeployment; nothing passes it around as a
// value; every one of them reads the certificate, locks the servers and locations and checks the location BEFORE it
// inserts; and the ACME planner reaches it only through prepareACMEDeployment.
func TestInsertDeploymentHasOnlyCheckedCallers(t *testing.T) {
	calls := deployHelperCalls(t)
	var inserters []string
	for fn, cs := range calls {
		for _, c := range cs {
			require.NotEqual(t, "insertDeployment(as a value)", c, "%s passes insertDeployment around", fn)
		}
		if slices.Contains(cs, "insertDeployment") {
			inserters = append(inserters, fn)
		}
	}
	slices.Sort(inserters)
	assert.Equal(t, []string{"RequestDeployment", "RequestKVDeployment", "insertDriftRepair", "planBinding", "prepareACMEDeployment"}, inserters)
	for _, fn := range inserters {
		cs := calls[fn]
		first := slices.Index(cs, "insertDeployment")
		for _, h := range []string{"readDeployCertificate", "lockDeployTargets", "checkDeployLocation"} {
			i := slices.Index(cs, h)
			assert.True(t, i >= 0 && i < first, "%s calls %s before insertDeployment: %v", fn, h, cs)
		}
	}
	assert.Equal(t, []string{"readDeployCertificate", "lockDeployTargets", "checkDeployLocation", "insertDeployment"}, calls["prepareACMEDeployment"],
		"prepareACMEDeployment runs the three checks in the order of RequestDeployment, then inserts")
	// The ACME planner and its helpers never call a deploy helper themselves: only through prepareACMEDeployment.
	for _, fn := range []string{"PlanACMEAutoDeploy", "planACMEDeploy", "readACMEDeploySnapshot", "holdACMEDeploy", "stopACMEDeploy",
		"acmeDeployCandidates", "planACMEAutoDeploy"} {
		assert.Empty(t, calls[fn], fn)
	}
}

// Every way to a deployment row in the ACME files goes through prepareACMEDeployment: no other function of the ACME
// files calls insertDeployment, and planACMEDeploy is the one that calls prepareACMEDeployment (DeployACMENow uses
// RequestDeployment).
func TestACMEFilesReachDeploymentsOnlyThroughTheCheckedPaths(t *testing.T) {
	files, err := filepath.Glob("acme_*.go")
	require.NoError(t, err)
	fset := token.NewFileSet()
	callers := map[string][]string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						switch sel.Sel.Name {
						case "prepareACMEDeployment", "insertDeployment", "RequestDeployment":
							callers[sel.Sel.Name] = append(callers[sel.Sel.Name], fn.Name.Name)
						}
					}
				}
				return true
			})
		}
	}
	assert.Equal(t, []string{"planACMEDeploy", "planACMEDeploy"}, callers["prepareACMEDeployment"], "the hold check and the deployments")
	assert.Equal(t, []string{"prepareACMEDeployment"}, callers["insertDeployment"])
	assert.Equal(t, []string{"DeployACMENow"}, callers["RequestDeployment"])
}

// The pure decision never reads the clock or a database: everything comes from the snapshot (a second call with the same
// snapshot gives the same plan).
func TestACMEAutoDeployPlanIsPure(t *testing.T) {
	f := newACMEPlanFixture()
	f.failed(f.a, time.Hour, "deployment.reload_failed")
	assert.Equal(t, planACMEAutoDeploy(f.sn), planACMEAutoDeploy(f.sn))
}

func TestACMEDeployTemplates(t *testing.T) {
	assert.Equal(t, []string{"acme.auto_deploy_stopped", "acme.auto_deploy_held_license", "acme.auto_deploy_held_chain", "acme.auto_deploy_untrusted"}, ACMEDeployTemplates())
	assert.Equal(t, map[string]string{"name": "a.example", "names": "a.example, b.example"}, acmeDeployParams([]string{"a.example", "b.example"}))
	assert.Equal(t, map[string]string{"names": ""}, acmeDeployParams(nil))
	assert.Equal(t, "ecdsa", policyAlgorithm("ecdsa_p384"))
	assert.Equal(t, "rsa", policyAlgorithm("rsa_3072"))
	assert.Equal(t, "other", policyAlgorithm("other"))
}
