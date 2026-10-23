# The real-Windows check

`.github/workflows/windows.yml` runs the Windows helper's real-host tests on GitHub's hosted Windows Server images
(`windows-2022` and `windows-2025`, Datacenter with Desktop Experience): the real tests and the fidelity tests of
`cmd/alice-winhelper` and `internal/providers/windows`, and the setup script smoke test. Its job `windows-required` is
the one check a branch protection rule should require. Decision R63, rulings in
`docs/superpowers/rulings/windows-iis.md` "W4 (R63)" (Rulings 4-10, 12, 15).

## The jobs

| Job (check name) | Runs on | What it does |
|---|---|---|
| `changes` | ubuntu-latest | Decides whether the Windows legs run (`windows=true` or `false`), see below. About a minute. |
| `linux-build` | ubuntu-latest | `make winhelper`, the build the release ships; passes the two SHA-256 values to the legs. Only when `changes` answered `true`. |
| `helper (windows-2022)`, `helper (windows-2025)` | the Windows images | Installs IIS, builds `alice-helper.exe` for amd64 and arm64 with the flags of `make winhelper` and fails when either differs from the Linux build by one byte, then runs the real-Windows tests. Every test of the workflow's `$required` list must print its `--- PASS` line: a skipped real test is a failure. Only when `changes` answered `true`. |
| `windows-required` | ubuntu-latest | Always runs (`if: always()`). Passes when `changes` succeeded and either answered `false` with `linux-build` and both `helper` legs skipped, or answered `true` with all of them succeeded. Any other combination fails: a failed, cancelled or skipped leg on a Windows change, or a failed `changes`. The decision is `deploy/dev/windows-ci.sh gate`. |

Only `windows-required` should be required. The legs' names change when GitHub retires an image, and a skipped leg
must not block a change that touches nothing Windows.

## What runs when

| Event | Base the change is measured against | Windows legs | A newer run of the same branch cancels it |
|---|---|---|---|
| Push to a branch other than the default branch | `git merge-base origin/<default> HEAD`: the whole branch, on every push | when the branch changes a watched path; no merge base: always | yes |
| Push to the default branch (`main`) | the push's `before` commit; an empty, all-zeros or unknown `before` (the branch's creation, a force push) runs the legs | when the push changes a watched path | no, and nothing displaces it: each default-branch push has a concurrency group of its own (`main-<sha>`), since a cancelled or displaced default-branch run would leave its Windows change untested |
| Pull request | the pull request's base commit | when the pull request changes a watched path | yes |
| Nightly (`41 2 * * *` UTC, the default branch) | none | always | no (its own concurrency group) |
| By hand (`workflow_dispatch`) | none | always | on a branch other than the default one, a push to that branch cancels it (both share the branch's group, and the push run cancels what is in progress); on the default branch a push never does (the push has its own group) |
| A release tag | `release.yml` calls the workflow with `all: true`; a tag push never starts it directly | always | no |

A base that is not a commit in the clone, or a failed `git diff`, answers `true`: an unknown base runs the legs, it
never skips them. GitHub keeps one pending run per concurrency group and cancels it when a newer one queues, whatever
`cancel-in-progress` says; that is why a push to the default branch, which is diffed from its `before` commit, gets a
group per commit: a queued push run displaced by the next push would leave its change untested, since the next push
diffs from it. On other branches the whole branch is diffed, so a displaced run loses nothing. A pull request from a branch of this repository runs twice (once for the push, once for the pull
request), as `ci.yml` does. There is no `merge_group` trigger: if a merge queue is ever enabled for `main`, add
`merge_group:` to `on:` of `windows.yml` (the required check must report for the queue's commits too).

In a run that `release.yml` started, the jobs appear under the caller's job name (`windows / windows-required`,
`windows / helper (windows-2022)` and so on); `release.yml`'s `stage` job waits for that call.

## Check names

Required (the owner configures it, below):

- `windows-required`

Informational (never required):

- `changes`
- `linux-build`
- `helper (windows-2022)`
- `helper (windows-2025)`

Recommended for the same rule, the owner's choice (`.github/workflows/ci.yml`):

- `go`
- `coverage`
- `ssh-matrix`
- `licensectl (ubuntu-latest)`
- `licensectl (macos-latest)`
- `web`
- `secrets`
- `stack`

## Making `windows-required` required (owner)

Nobody but the repository owner changes repository settings. The rule below requires `windows-required` on the
default branch, lets the repository admin role bypass it (the owner pushes `main` directly; the coordinator pushes a
phase branch first, so the commit fast-forwarded onto `main` already has a green `windows-required`), and does not
require the branch to be up to date before merging.

```
gh api --method POST repos/erenmeren/alice/rulesets --input - <<'EOF'
{"name":"main: windows-required","target":"branch","enforcement":"active",
 "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
 "bypass_actors":[{"actor_id":5,"actor_type":"RepositoryRole","bypass_mode":"always"}],
 "rules":[{"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":false,
   "do_not_enforce_on_create":false,"required_status_checks":[{"context":"windows-required","integration_id":15368}]}}]}
EOF
```

`integration_id` 15368 is GitHub Actions, so only a check reported by a workflow satisfies the rule. To add the
recommended `ci.yml` checks, add one `{"context":"<name>","integration_id":15368}` per name to
`required_status_checks`.

The same in the web interface: **Settings → Rules → Rulesets → New ruleset → New branch ruleset**. Name it
`main: windows-required`, set **Enforcement status** to **Active**, under **Target branches** add the default branch
(**Include default branch**), under **Bypass list** add **Repository admin** with **Always allow**, tick **Require
status checks to pass**, choose **Add checks**, type `windows-required` and pick the one from **GitHub Actions**, and
leave **Require branches to be up to date before merging** off. Save.

Check it:

```
gh api repos/erenmeren/alice/rules/branches/main
```

The answer lists a `required_status_checks` rule whose `required_status_checks` hold `windows-required`.
`docs/release-checklist.md` row 1.47 records it.

The first check after `main` has the W4 workflow (a coordinator step): the first push to `main` that changes no
watched path, or a branch cut from that `main` with such a change only, must show `changes` with `windows=false`,
`linux-build` and both `helper` legs **skipped**, and `windows-required` **successful** under exactly that name (F14's
skipped path; it could not be observed on the W4 branch itself, whose merge base was the W2 `main`).

## Running it by hand

```
gh workflow run windows.yml --ref <branch>
gh run list --workflow windows.yml --branch <branch> --limit 3
gh run watch <run id>
```

A manual run always runs both legs. On a branch other than the default one, a push to that branch while it runs
cancels it; a push to the default branch never cancels or displaces anything.

## The nightly run

The nightly run tests the default branch on both images every night, so a change of the images themselves (a Windows
update, a new OpenSSH or IIS build) shows up even when nobody changes Windows code. A failure is reported by GitHub's
own workflow e-mail to the people who watch the repository's Actions; Alice sends nothing. GitHub pauses scheduled
workflows of a public repository after 60 days without activity in the repository: the Actions tab then shows the
workflow as disabled; enable it again there or with `gh workflow enable windows.yml`.

## The watched list

`.github/windows-paths.txt` names the paths whose change runs the legs: one entry per line, `#` starts a comment.

- `dir/**`: every file below `dir`;
- `dir/*`: the files directly in `dir`;
- a plain path: that file only.

Any other form is refused (exit 2 of `deploy/dev/windows-ci.sh changed`, which fails `changes` and so the gate).
`internal/archtest:TestWindowsWorkflowWatchesEveryDependency` keeps the list complete: every package that
`GOOS=windows go list -deps -test` names for `./cmd/alice-winhelper/...` and `./internal/providers/windows/...` (tags
`""` and `alicetest`) must be matched, the fixed entries (the workflow, the list, the script, `go.mod`, `go.sum`, the
`Makefile` and `docs/windows-host-preparation.md`) must be there, and every entry must match a tracked file.

To add a package: when the Windows code or its tests start importing a new package, that test fails and names its
directory. Add `<dir>/**` (or `<dir>/*` for that directory's files only) to `.github/windows-paths.txt`, then run

```
go test -count=1 ./internal/archtest -run 'TestWindows'
```

Remove an entry once nothing it names exists any more (the same test refuses a stale entry). A new `TestReal*` or
`TestFidelity*` function must also be added to the `$required` list of `windows.yml`
(`TestWindowsWorkflowRequiresEveryRealTest` fails until it is), and a change of the helper's build flags must be made
in the `Makefile`, `deploy/dev/reproducible-check.sh`, `deploy/Dockerfile` and `windows.yml` together
(`TestWindowsHelperBuildFlagsAgree`).
