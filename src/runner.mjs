// S3: the runner -- the only module in this project that starts a process.
//
// This is where the central claim is either true or false. Everything upstream
// (policy, names, validation) exists to get here with one thing: an argv array
// that was never a string. The process is started with `shell: false`, so
// there is no shell to interpret `&&`, `|`, `$(...)` or redirection. Those
// characters are ordinary bytes inside an argument, which is why the policy
// layer is free to accept them.
//
// Every failure mode is a returned value, never an exception. Callers are
// long-running gates, and a gate that throws turns one bad command into an
// outage.
//
// Bounds are enforced here rather than trusted: a timeout so a chat-triggered
// command cannot hang forever, and an output cap so a chatty process cannot
// fill memory. Both limits are the reason this module is not a one-liner
// around spawn.

import { spawn } from 'node:child_process';

const DEFAULT_TIMEOUT_SECONDS = 60;
const DEFAULT_MAX_OUTPUT_BYTES = 65536;
const KILL_SIGNAL = 'SIGTERM';

/**
 * Run one declared command.
 *
 * @param {{command: {argv: string[], cwd?: string|null, timeout_seconds?: number, max_output_bytes?: number}, spawnImpl?: Function, now?: Function}} input
 * @returns {Promise<{verdict: 'ok'|'failed'|'timedOut'|'spawn-failed', reason: string|null, exitCode: number|null, signal: string|null, durationMs: number, stdout: string, stderr: string, stdoutBytes: number, stderrBytes: number, truncated: {stdout: boolean, stderr: boolean}}>}
 */
export function runCommand({ command, spawnImpl = spawn, now = Date.now }) {
  const timeoutMs = (command.timeout_seconds ?? DEFAULT_TIMEOUT_SECONDS) * 1000;
  const cap = command.max_output_bytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const [file, ...args] = command.argv;
  const startedAt = now();

  return new Promise((resolve) => {
    let settled = false;
    let timer = null;

    const buffers = { stdout: [], stderr: [] };
    const kept = { stdout: 0, stderr: 0 };
    const seen = { stdout: 0, stderr: 0 };
    const truncated = { stdout: false, stderr: false };

    const finish = ({ verdict, reason = null, exitCode = null, signal = null }) => {
      // First outcome wins. A process killed by the timeout still emits
      // 'close' afterwards, and letting that second event overwrite the
      // verdict would silently turn every timeout into a failure.
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);

      resolve({
        verdict,
        reason,
        exitCode,
        signal,
        durationMs: now() - startedAt,
        // Byte counts describe what the process PRODUCED; the returned text is
        // what we were willing to keep. The gap between them is the
        // truncation, which is why both are reported.
        stdout: Buffer.concat(buffers.stdout).toString('utf8'),
        stderr: Buffer.concat(buffers.stderr).toString('utf8'),
        stdoutBytes: seen.stdout,
        stderrBytes: seen.stderr,
        truncated: { stdout: truncated.stdout, stderr: truncated.stderr },
      });
    };

    const collect = (name) => (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      seen[name] += buffer.length;

      // Keep draining after the cap is reached: destroying the stream would
      // leave the child blocked on a full pipe and turn a long run into a
      // hang, which is worse than losing output we already declared lost.
      const room = cap - kept[name];
      if (room <= 0) {
        truncated[name] = true;
        return;
      }
      if (buffer.length > room) {
        buffers[name].push(buffer.subarray(0, room));
        kept[name] = cap;
        truncated[name] = true;
        return;
      }
      buffers[name].push(buffer);
      kept[name] += buffer.length;
    };

    let child;
    try {
      child = spawnImpl(file, args, {
        // `undefined`, not a default: omitting cwd means "inherit the caller's",
        // and inventing a directory here would be a silent policy decision.
        cwd: command.cwd ?? undefined,
        // The security boundary in one line. With a shell, every argument
        // becomes source code; without one, it stays a string.
        shell: false,
        windowsHide: true,
        // stdin is closed rather than inherited: a command that prompts would
        // wait forever on a channel with no way to answer.
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      finish({ verdict: 'spawn-failed', reason: `spawn failed: ${error.message}` });
      return;
    }

    if (child.stdout) child.stdout.on('data', collect('stdout'));
    if (child.stderr) child.stderr.on('data', collect('stderr'));

    child.on('error', (error) => {
      finish({ verdict: 'spawn-failed', reason: `spawn failed: ${error.code ?? error.message}` });
    });

    child.on('close', (code, signal) => {
      if (signal) {
        finish({ verdict: 'failed', reason: `terminated by ${signal}`, signal });
        return;
      }
      finish({ verdict: code === 0 ? 'ok' : 'failed', exitCode: code ?? null });
    });

    timer = setTimeout(() => {
      try {
        child.kill(KILL_SIGNAL);
      } catch {
        // Already gone. The timeout verdict stands either way.
      }
      finish({ verdict: 'timedOut', reason: `exceeded ${timeoutMs}ms` });
    }, timeoutMs);
  });
}
