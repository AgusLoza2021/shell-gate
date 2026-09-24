// S3: the runner. This is the only module that starts a process, and the one
// place where the project's central claim is either true or false: arguments
// are PASSED, never parsed.
//
// The tests split into two kinds on purpose. Injected fakes cover the failure
// paths -- a missing executable, a timeout, a chatty process -- without
// waiting on a real machine. Real child processes cover the claim itself,
// because a mocked shell is exactly the wrong instrument for proving that no
// shell is used.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { resolve as resolvePath } from 'node:path';

import { runCommand } from '../src/runner.mjs';

const NODE = process.execPath;

function command(argv, overrides = {}) {
  return { argv, cwd: null, timeout_seconds: 60, max_output_bytes: 65536, approval: 'always', ...overrides };
}

/** A stand-in for the object node:child_process returns. */
function fakeChild({ withStreams = true } = {}) {
  const child = new EventEmitter();
  if (withStreams) {
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
  }
  child.kills = [];
  child.kill = (signal) => {
    child.kills.push(signal ?? 'SIGTERM');
    return true;
  };
  return child;
}

function spawnReturning(child) {
  const calls = [];
  const impl = (file, args, options) => {
    calls.push({ file, args, options });
    return child;
  };
  return { impl, calls };
}

describe('runner: a real process is started without a shell', () => {
  test('a successful command reports its exit code and output', async () => {
    const result = await runCommand({ command: command([NODE, '-e', 'process.stdout.write("hello")']) });
    assert.equal(result.verdict, 'ok');
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, 'hello');
    assert.equal(result.stderr, '');
    assert.equal(result.stdoutBytes, 5);
    assert.deepEqual(result.truncated, { stdout: false, stderr: false });
  });

  // The test the repository exists for. Each argument contains shell syntax;
  // the child must receive all of it literally. If a shell were involved
  // anywhere, `&& echo PWNED` would become a second command and the assertion
  // on the exact stdout would fail -- so this test fails loudly if someone
  // "simplifies" the runner into an exec string.
  test('shell metacharacters arrive as literal arguments, never as syntax', async () => {
    const payload = ['a && echo PWNED', '$(whoami)', 'a;b', '`id`', 'x > out.txt'];
    const result = await runCommand({
      command: command([
        NODE,
        '-e',
        'process.stdout.write(process.argv.slice(1).join("|"))',
        ...payload,
      ]),
    });
    assert.equal(result.verdict, 'ok');
    assert.equal(result.stdout, payload.join('|'));
    assert.equal(result.stdout.includes('PWNED\n'), false);
  });

  test('a non-zero exit is a reported outcome, not an exception', async () => {
    const result = await runCommand({ command: command([NODE, '-e', 'process.exit(3)']) });
    assert.equal(result.verdict, 'failed');
    assert.equal(result.exitCode, 3);
  });

  test('stderr is captured separately from stdout', async () => {
    const result = await runCommand({
      command: command([NODE, '-e', 'process.stdout.write("out"); process.stderr.write("boom")']),
    });
    assert.equal(result.stdout, 'out');
    assert.equal(result.stderr, 'boom');
    assert.equal(result.stderrBytes, 4);
  });

  test('output beyond the cap is dropped and the loss is reported', async () => {
    const result = await runCommand({
      command: command([NODE, '-e', 'process.stdout.write("x".repeat(1000))'], { max_output_bytes: 10 }),
    });
    assert.equal(result.stdout.length, 10);
    assert.deepEqual(result.truncated, { stdout: true, stderr: false });
    // The count still describes what the process actually produced, so the
    // owner can tell "small output" from "we threw most of it away".
    assert.equal(result.stdoutBytes, 1000);
  });

  test('a working directory is honoured', async () => {
    const cwd = resolvePath('src');
    const result = await runCommand({
      command: command([NODE, '-e', 'process.stdout.write(process.cwd())'], { cwd }),
    });
    const reported = result.stdout;
    const normalize = (value) => (process.platform === 'win32' ? value.toLowerCase() : value);
    assert.equal(normalize(reported), normalize(cwd));
  });

  test('an executable that does not exist fails closed', async () => {
    const result = await runCommand({
      command: command(['shell-gate-definitely-not-a-real-binary-9f3a']),
    });
    assert.equal(result.verdict, 'spawn-failed');
    assert.ok(result.reason.length > 0);
    assert.equal(result.exitCode, null);
  });
});

describe('runner: the spawn call is the security boundary', () => {
  test('spawn is called with shell disabled', async () => {
    const child = fakeChild();
    const { impl, calls } = spawnReturning(child);
    const pending = runCommand({ command: command(['git', 'status']), spawnImpl: impl });
    child.emit('close', 0, null);
    await pending;

    assert.equal(calls.length, 1);
    assert.equal(calls[0].options.shell, false);
  });

  test('arguments are passed positionally, never joined into one string', async () => {
    const child = fakeChild();
    const { impl, calls } = spawnReturning(child);
    const pending = runCommand({
      command: command(['git', 'commit', '-m', 'fix: a && b']),
      spawnImpl: impl,
    });
    child.emit('close', 0, null);
    await pending;

    assert.equal(calls[0].file, 'git');
    assert.deepEqual(calls[0].args, ['commit', '-m', 'fix: a && b']);
  });

  test('stdin is not inherited: a prompt must not hang a chat-triggered run', async () => {
    const child = fakeChild();
    const { impl, calls } = spawnReturning(child);
    const pending = runCommand({ command: command(['git', 'status']), spawnImpl: impl });
    child.emit('close', 0, null);
    await pending;

    assert.equal(calls[0].options.stdio[0], 'ignore');
  });

  test('an injected spawn that throws is reported, never propagated', async () => {
    const result = await runCommand({
      command: command(['git']),
      spawnImpl: () => {
        throw new Error('EINVAL: spawn failed');
      },
    });
    assert.equal(result.verdict, 'spawn-failed');
    assert.match(result.reason, /EINVAL/);
  });

  test('a spawn error event is reported with its code', async () => {
    const child = fakeChild();
    const { impl } = spawnReturning(child);
    const pending = runCommand({ command: command(['nope']), spawnImpl: impl });
    const error = new Error('spawn nope ENOENT');
    error.code = 'ENOENT';
    child.emit('error', error);
    const result = await pending;

    assert.equal(result.verdict, 'spawn-failed');
    assert.match(result.reason, /ENOENT/);
  });
});

describe('runner: a command cannot outrun its bounds', () => {
  test('a command that overruns its timeout is killed and reported as timedOut', async () => {
    const child = fakeChild();
    const { impl } = spawnReturning(child);
    // The fake never closes, so only the timeout can settle this call.
    const result = await runCommand({
      command: command(['sleep', 'forever'], { timeout_seconds: 1 }),
      spawnImpl: impl,
    });

    assert.equal(result.verdict, 'timedOut');
    assert.equal(result.exitCode, null);
    assert.equal(child.kills.length, 1);
    assert.ok(result.reason.length > 0);
  });

  test('a close event arriving after the timeout does not rewrite the outcome', async () => {
    const child = fakeChild();
    const { impl } = spawnReturning(child);
    const result = await runCommand({
      command: command(['sleep', 'forever'], { timeout_seconds: 1 }),
      spawnImpl: impl,
    });
    child.emit('close', 0, null);

    assert.equal(result.verdict, 'timedOut');
  });

  test('a process killed by a signal is a failure carrying the signal', async () => {
    const child = fakeChild();
    const { impl } = spawnReturning(child);
    const pending = runCommand({ command: command(['sleep', '1']), spawnImpl: impl });
    child.emit('close', null, 'SIGTERM');
    const result = await pending;

    assert.equal(result.verdict, 'failed');
    assert.equal(result.exitCode, null);
    assert.equal(result.signal, 'SIGTERM');
  });

  test('the duration is measured from the injected clock', async () => {
    const child = fakeChild();
    const { impl } = spawnReturning(child);
    const ticks = [1000, 1250];
    const pending = runCommand({
      command: command(['git']),
      spawnImpl: impl,
      now: () => ticks.shift() ?? 1250,
    });
    child.emit('close', 0, null);
    const result = await pending;

    assert.equal(result.durationMs, 250);
  });

  // Every caller of this module is a long-running gate, and a gate that throws
  // turns one bad command into an outage. The contract is a value, always.
  test('the runner resolves instead of rejecting, whatever spawnImpl does', async () => {
    const thrown = await runCommand({
      command: command(['git']),
      spawnImpl: () => {
        throw new Error('boom');
      },
    });
    assert.equal(thrown.verdict, 'spawn-failed');

    const failing = fakeChild();
    const first = spawnReturning(failing);
    const pending = runCommand({ command: command(['git']), spawnImpl: first.impl });
    failing.emit('error', new Error('boom'));
    assert.equal(typeof (await pending).verdict, 'string');

    const closing = fakeChild();
    const second = spawnReturning(closing);
    const waiting = runCommand({ command: command(['git']), spawnImpl: second.impl });
    closing.emit('close', 0, null);
    assert.equal(typeof (await waiting).verdict, 'string');
  });
});
