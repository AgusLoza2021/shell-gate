# shell-gate

Run a **declared** set of local commands by name. Default-deny, argv-only, no
shell, every run audited.

```console
$ shell-gate run verify
ℹ tests 106
ℹ pass 106
ℹ fail 0
shell-gate: verify ok (exit 0, 2432ms)
```

> **Status: v0.1.0, command line only.** There is no chat adapter yet — that is
> the point of this layer, not an omission. See [Roadmap](#roadmap).

---

## Why this exists

Remote control of a PC usually starts with "let me just run shell commands from
my phone". That design hands a chat channel a shell on your machine, and every
message becomes a potential command. The channel that is convenient is also the
channel you cannot fully trust: accounts get phished, tokens leak, and a typo in
a message is indistinguishable from an instruction.

`shell-gate` inverts the direction. The machine owns the list, and the channel
can only ask for a name from that list.

```
        what usually happens                 what shell-gate does
   message ──▶ shell ──▶ anything        message ──▶ name ──▶ ┌─ not declared? REFUSED
                                                             └─ declared? run THAT argv
```

A caller never sends a command. A caller sends a **name**. The name either exists
in a policy file on this machine, or it does not exist at all.

## Quick start

```console
git clone <this repo> && cd shell-gate
node bin/shell-gate.mjs list
```

```
shell-gate: 4 command(s) declared in shell-gate.json
  verify               never  Run the whole test suite
  status               never  Show the working tree
  history              never  Show the last ten commits
  publish              always Push the current branch: the one command worth asking about every time
```

Then ask what a name would do, without doing it, and run it:

```console
$ node bin/shell-gate.mjs check status
status: allowed
  description  Show the working tree
  argv         git status --short
  cwd          (inherited)
  timeout      60s
  max output   65536 bytes
  approval     never

$ node bin/shell-gate.mjs run status
?? shell-gate.json
shell-gate: status ok (exit 0, 48ms)
```

Some commands should ask first. `publish` is declared `approval: always`, so it
can be decided in the moment, or decided now and spent later:

```console
$ node bin/shell-gate.mjs run publish
shell-gate: "publish" requires approval: no approval for "publish"
shell-gate: re-run with --yes to approve it now, or record one in advance: shell-gate approve publish

$ node bin/shell-gate.mjs approve publish     # one decision, one use
```

Requires Node.js 24+. Zero dependencies.

## The policy

One JSON file (`shell-gate.json` by default, `--policy=<path>` to change it).

```json
{
  "version": 1,
  "commands": {
    "status": {
      "description": "Show the working tree",
      "argv": ["git", "status", "--short"],
      "approval": "never"
    },
    "publish": {
      "description": "Push the current branch",
      "argv": ["git", "push"],
      "timeout_seconds": 120,
      "approval": "always"
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `argv` | **Required.** The command as an array. The one field that decides what runs. |
| `description` | Shown by `list` and `check`. Purely for humans. |
| `cwd` | Absolute directory to run in. Omitted means inherit the caller's. |
| `timeout_seconds` | Kill the command after this. Default `60`. |
| `max_output_bytes` | Per-stream output cap. Default `65536`. |
| `approval` | `always` or `never`. **Defaults to `always`.** |

Three decisions in that table are deliberate, and each one favours the cautious
side:

- **`approval` defaults to `always`.** A field you forgot costs you a prompt, not
  a silent execution.
- **An unknown key is an error, never a silent default.** `"timeout": 300` is a
  typo for `timeout_seconds`, and a policy that quietly ignores it leaves you
  believing a command is bounded when it is not.
- **A wrong `version` is rejected.** Reading a future format with today's rules
  could reinterpret a field whose meaning changed. A policy is a security
  boundary, so an unrecognised version fails closed.

## Approving in advance

`approval: always` means "a human has to decide". Until v0.2.0 the only way to
decide was `--yes`, which requires being at the keyboard. An agent, a scheduled
task or a message from a phone has nobody sitting there, so the decision had to
be able to outlive the invocation that made it.

`shell-gate approve <name>` writes that decision down. The next run of that name
spends it, and it is gone.

```console
$ node bin/shell-gate.mjs run publish
shell-gate: "publish" requires approval: no approval for "publish"
shell-gate: re-run with --yes to approve it now, or record one in advance: shell-gate approve publish

$ node bin/shell-gate.mjs approve publish
approved: publish (one use)
  fingerprint  2aa369e6d42ad282
  granted at   2026-09-24T17:29:44.636Z
  expires      2026-09-24T17:39:44.636Z

$ node bin/shell-gate.mjs run publish
<git's own output here>
shell-gate: publish ok (exit 0, 1240ms)

$ node bin/shell-gate.mjs run publish
shell-gate: "publish" requires approval: no approval for "publish"
```

Three ways to be refused, and each one is a different situation:

| What happened | Reason you will see | What it means |
| --- | --- | --- |
| Nothing was ever approved | `no approval for "publish"` | Nobody has decided yet |
| The policy changed afterwards | `...was granted for a different command: the policy changed after it was approved` | The decision was real, but not for *this* |
| It aged out | `...expired at 2026-09-24T17:39:44.636Z` | The decision was real, and is no longer live |

The second row is the reason this is a fingerprint and not a name. An approval
keyed by name records "someone said yes to `publish`". An approval keyed by
fingerprint records "someone said yes to this exact program, these exact
arguments, in this exact directory". Without that binding, editing `argv` after
the fact — `git push` to `git push --force` — would spend a decision nobody
made, and a policy edit does not look like a security event.

| Flag | Meaning |
| --- | --- |
| `--ttl=<seconds>` | How long the decision stays live. Default `600` (ten minutes). |
| `--approvals=<path>` | Where decisions are stored. Default `approvals.json`. |

`--yes` still works, and wins when there is someone at the keyboard: a decision
made in the moment costs nothing that a later invocation could have spent, so it
does not consume a stored one. `--json` reports `"outcome":"granted"` with the
fingerprint and expiry, so a caller can hand the expiry to a human.

Two rules here exist to fail safely:

- **An approvals file that cannot be read grants nothing.** A decision that
  cannot be verified is not a decision, so the command refuses to run (exit 6)
  and says why.
- **A malformed approvals file is not a partial one.** One unreadable entry
  invalidates the whole document, for the same reason an unknown policy
  `version` does.

The store is a plain file, and it is listed in `.gitignore`. Commit it and you
have committed a live permission.

## Exit codes

Each outcome has its own number, because that number is the only channel a
script, a scheduled task or a future chat adapter can act on without parsing
prose.

| Code | Meaning |
| --- | --- |
| `0` | Ran and exited 0 |
| `1` | Usage error |
| `2` | The policy is missing, unreadable or invalid |
| `3` | The name is not declared in the policy |
| `4` | Approval is required and no usable approval was found |
| `5` | The command ran and exited non-zero |
| `6` | The command timed out, could not start, or its record could not be written |

`--json` prints one machine-readable line per invocation, including for refusals.

## The audit log

Every outcome is appended to `audit/shell-gate.jsonl` — **including the refusals**.
A gate whose only record is "it worked" hides the half that matters later: a
denial that leaves no trace cannot be told apart from a request that never
arrived.

```json
{"at":"2026-09-24T17:09:41.663Z","command":"verify","outcome":"ok","reason":null,
 "fingerprint":"2aa369e6d42ad282","argv":["node","--test","tests/*.test.mjs"],
 "cwd":null,"exitCode":0,"durationMs":2432,"stdoutBytes":8886,"stderrBytes":0,
 "truncated":{"stdout":false,"stderr":false},"approval":"not-required"}
```

Every line has the same shape, including the ones that describe something other
than a run. A grant is an event too, and without recording it the log could show
a command executed with a stored approval and no evidence of anyone having
stored anything:

```json
{"at":"2026-09-24T17:29:44.638Z","command":"publish","outcome":"granted","reason":null,
 "fingerprint":"2aa369e6d42ad282","argv":["git","push"],"cwd":null,"exitCode":null,
 "durationMs":null,"stdoutBytes":null,"stderrBytes":null,"truncated":null,
 "approval":"stored"}
```

The `approval` field says how the run came to be authorised:

| Value | Meaning |
| --- | --- |
| `not-required` | Declared `approval: never` |
| `interactive` | Decided in the moment with `--yes` |
| `stored` | A recorded decision from `approve` was spent |
| `null` | Nothing was authorised — a refusal, or the value was not recorded |

Byte counts and durations are `null` for anything that did not execute, since a
process that never started has nothing to measure. `approval` is deliberately
not blanked that way: it is provenance, not a measurement, and an approval spent
on a command that then failed to start is exactly the fact worth keeping.

Records are built as values, never as views over live objects, so nothing that
happens later can rewrite what was logged. The log is opened `0600` (owner-only
on POSIX) because it is a map of your machine's capabilities. A record that
cannot be written is reported as a failure — exit 6 — rather than swallowed.

## Threat model

Being precise about this matters more than being impressive.

**What this design does defend against**

- **Command injection through the channel.** Arguments are passed to the process
  as an array with `shell: false`. There is no shell to interpret `&&`, `|`,
  `$(...)`, backticks or redirection, so those characters are ordinary bytes
  inside an argument. This is not a filtering rule that can be bypassed — there
  is no parser to bypass.
- **Reaching commands that were never granted.** Resolution is an exact key
  match: no prefix matching, no case folding, no trimming, no "did you mean".
  It uses `Object.hasOwn` rather than a property lookup, so inherited keys like
  `toString` and `constructor` cannot resolve to anything.
- **A caller claiming a command is something else.** Each command has a
  deterministic fingerprint (program, arguments, working directory), so an
  approval granted for one exact action cannot be silently reinterpreted as
  another.
- **Replaying a decision.** A stored approval is removed as it is spent, in the
  same step that reports it as spent.
- **A decision surviving a policy edit.** An approval names a fingerprint, not a
  name, so changing what a command does invalidates the decision instead of
  widening it.
- **A decision surviving indefinitely.** An approval carries its own expiry, and
  is dropped rather than kept around once it has passed.
- **Runaway commands.** Every command is bounded in time and output.
- **Unaccountable runs.** Refusals, executions and granted decisions alike are
  recorded.

**What this does NOT defend against**

- **A compromised machine.** If an attacker can already write to
  `shell-gate.json` or replace a binary on your `PATH`, the gate is irrelevant.
- **An unsafe command you declared yourself.** The gate enforces *which* command
  runs, not whether that command is wise.
- **A malicious executable.** `shell-gate` does not sandbox anything. Every
  command runs with your full user privileges, with your environment.
- **Interception of your channel.** Payloads are not signed or encrypted here.
  That belongs to the transport, and it is not implemented yet.
- **Anyone who can write the approvals file.** Stored decisions are not signed.
  The design assumes the disk is yours; an attacker who can already write
  `approvals.json` does not need to forge anything.
- **Two processes racing on one approval.** The read and the write are separate
  system calls, so two invocations started at the same moment can both find the
  same decision unused. Writes are atomic — the file is never half-written — but
  the decision itself is not locked. Use one gate at a time.

If you want a sandbox, `shell-gate` is not one and does not pretend to be. What
it gives you is that the set of things your phone can make this PC do is a file
you can read in one sitting.

## Known limitations

Documented rather than discovered later. Several of these are deliberate
non-goals; none of them are silent.

- **`argv` is not a sandbox.** A declared command can do anything your account
  can do. The allowlist constrains the channel, not the program.
- **`.cmd` and `.bat` shims cannot run at all on Windows.** Verified on Node
  24: `spawn('npm', ...)` fails `ENOENT`, and `spawn('npm.cmd', ...)` fails
  `EINVAL`, because Node refuses to execute a batch shim without a shell
  (its fix for argument injection in `.cmd`). So `npm`, `npx` and similar
  wrappers are unusable as the executable; point `argv[0]` at the real
  program instead — `node`, `git`, or a full path to a `.exe`. The policy in
  this repository runs `node --test` for exactly that reason.
- **The working directory is trusted.** `cwd` comes from the policy, which is
  trusted input; when omitted, the caller's directory is inherited.
- **The environment is inherited.** Declared commands see every environment
  variable you have.
- **Output is not redacted.** Anything a command prints is logged and returned.
  Do not declare a command that prints secrets.
- **The log has no rotation.** It grows one line per invocation, forever.
- **Killing a timeout kills one process, not a tree.** On Windows, a grandchild
  started by the command may survive.
- **A byte cap can split a multi-byte character.** The cap is in bytes; a
  truncated UTF-8 sequence is replaced when decoded. Raw byte counts are
  reported separately so the truncation stays visible.
- **The file mode is a POSIX guarantee.** `0600` is meaningful on Linux and
  macOS; Windows ACLs are a separate mechanism this tool does not manage.
- **One approval is not a lock.** See the racing note in the threat model: an
  approval is spent once, but two simultaneous runs can both read it first.
- **Approvals are keyed by name and fingerprint, not by caller.** A stored
  approval does not record who asked. It records that the decision was made, so
  anyone who can invoke `shell-gate` with that name can spend it.

## Roadmap

**v0.1.0.** Policy, argv-only runner, audit log, CLI. Done and tested.

**v0.2.0 — this repository.** One-use approval bound to a command fingerprint,
with its own expiry, refusing on drift. Done and tested; the three refusal cases
are exercised against a real filesystem, not only against mocks.

**Next, in order:**

1. **A policy linter.** `shell-gate check --all` to surface a policy whose
   `cwd` does not exist, or whose `argv[0]` is not resolvable, before you need
   it at 2 a.m.
2. **Log rotation and a `tail` subcommand.** The log is append-only and has no
   consumer yet.
3. **A chat adapter.** Only after the gate is trustworthy, and it will import
   the gate rather than reimplement any of it.

Not planned: a sandbox, a scheduler, a web UI, or supporting arbitrary shell
strings. Each of those would make the safe path the slower path.

## Development

```console
npm test          # 182 tests, node:test, no dependencies
node bin/shell-gate.mjs run verify   # the gate runs its own suite
```

The suite has one unusual property worth mentioning: it contains tests with no
injected collaborators, running against the real filesystem and real child
processes. That is deliberate. An early version passed 101 tests while being
unable to run a single real command, because every test used a fake filesystem
and the fake could not report that `audit/` did not exist. Mocks answer the
question the test asks; at least some tests have to ask the question the tool
actually faces.

`src/` is layered so each file can be tested on its own:

| File | Responsibility |
| --- | --- |
| `src/policy.mjs` | Text → validated commands, and the fingerprint a decision binds to. Pure: no filesystem, no process, no clock. |
| `src/approval.mjs` | Stored decisions: one use, one fingerprint, one expiry. Atomic writes, fails closed. |
| `src/runner.mjs` | The only module that starts a process. Enforces the timeout and output caps. |
| `src/audit.mjs` | Builds and appends records. Never throws. |
| `src/cli.mjs` | Flags, output, exit codes. All collaborators injectable. |
| `bin/shell-gate.mjs` | Five lines: supplies the real arguments and the real process. |

## License

MIT. See [LICENSE](LICENSE).
