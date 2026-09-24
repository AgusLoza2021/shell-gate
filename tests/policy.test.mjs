// S2: policy engine. Every decision here is a pure function over text, so the
// whole surface is testable without a filesystem, a process, or a clock.
//
// Both failure directions are tested, because both are real failures. An
// undeclared name must be denied. But a legitimate argument -- a commit
// message containing '&&', a Windows path with spaces -- must NOT be rejected:
// a gate that over-blocks is a gate the owner switches off, and a gate that is
// switched off protects nothing.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { resolve as resolvePath } from 'node:path';

import {
  parsePolicy,
  resolveCommand,
  validateArgv,
  fingerprintCommand,
} from '../src/policy.mjs';

// Built through node:path so the test is not Windows-only by accident.
const ABSOLUTE_CWD = resolvePath('project');

function policyText(commands, extra = {}) {
  return JSON.stringify({ version: 1, commands, ...extra });
}

function command(overrides = {}) {
  return { description: 'Run the test suite', argv: ['node', '--test'], ...overrides };
}

function parseOrFail(text) {
  const result = parsePolicy(text);
  assert.equal(result.verdict, 'ok', `expected ok, got ${JSON.stringify(result)}`);
  return result.policy;
}

describe('policy: parsePolicy accepts a well-formed policy', () => {
  test('the minimal policy parses', () => {
    const policy = parseOrFail(policyText({ test: command() }));
    assert.deepEqual(Object.keys(policy.commands), ['test']);
    assert.deepEqual(policy.commands.test.argv, ['node', '--test']);
  });

  test('approval defaults to always: the safe default, not the convenient one', () => {
    const policy = parseOrFail(policyText({ test: command() }));
    assert.equal(policy.commands.test.approval, 'always');
  });

  test('timeout_seconds and max_output_bytes default when omitted', () => {
    const policy = parseOrFail(policyText({ test: command() }));
    assert.equal(policy.commands.test.timeout_seconds, 60);
    assert.equal(policy.commands.test.max_output_bytes, 65536);
  });

  test('explicit values are preserved', () => {
    const policy = parseOrFail(
      policyText({
        build: command({
          argv: ['npm', 'run', 'build'],
          cwd: ABSOLUTE_CWD,
          timeout_seconds: 900,
          max_output_bytes: 1024,
          approval: 'never',
        }),
      }),
    );
    assert.equal(policy.commands.build.timeout_seconds, 900);
    assert.equal(policy.commands.build.max_output_bytes, 1024);
    assert.equal(policy.commands.build.approval, 'never');
    assert.equal(policy.commands.build.cwd, ABSOLUTE_CWD);
  });

  test('cwd is null when the policy omits it', () => {
    const policy = parseOrFail(policyText({ test: command() }));
    assert.equal(policy.commands.test.cwd, null);
  });

  test('declared names may contain dots, dashes and underscores', () => {
    const policy = parseOrFail(
      policyText({
        'git.status': command(),
        'restart-broker': command(),
        run_tests: command(),
        'node24.test-runner': command(),
      }),
    );
    assert.equal(Object.keys(policy.commands).length, 4);
  });

  test('description is optional', () => {
    const policy = parseOrFail(policyText({ test: { argv: ['node', '--test'] } }));
    assert.equal(policy.commands.test.description, '');
  });
});

describe('policy: parsePolicy fails closed', () => {
  const malformed = [
    ['a non-string input', 42],
    ['a null input', null],
    ['an empty string', ''],
    ['text that is not JSON', '{oops'],
    ['a JSON array at the top level', JSON.stringify([{ version: 1, commands: {} }])],
    ['a JSON string at the top level', JSON.stringify('hello')],
    ['a missing version', JSON.stringify({ commands: { test: command() } })],
    ['an unknown version', policyText({ test: command() }, { version: 2 })],
    ['a string version', policyText({ test: command() }, { version: '1' })],
    ['missing commands', JSON.stringify({ version: 1 })],
    ['an empty commands map', policyText({})],
    ['commands as an array', policyText([command()])],
    ['commands as a string', policyText('test')],
  ];

  for (const [label, text] of malformed) {
    test(`${label} is rejected`, () => {
      const result = parsePolicy(text);
      assert.equal(result.verdict, 'invalid');
      assert.ok(Array.isArray(result.errors) && result.errors.length > 0, 'has errors');
    });
  }

  test('a rejected policy carries no usable commands', () => {
    const result = parsePolicy(policyText({ test: { argv: [] } }));
    assert.equal(result.verdict, 'invalid');
    assert.equal(result.policy, undefined);
  });

  test('an invalid command name is rejected', () => {
    for (const name of ['Test', 'has space', '-leading', 'UPPER', 'con mayúsculas']) {
      const result = parsePolicy(policyText({ [name]: command() }));
      assert.equal(result.verdict, 'invalid', `"${name}" must be rejected`);
    }
  });

  test('structural errors inside a command are rejected and accumulate', () => {
    const result = parsePolicy(
      policyText({
        broken: {
          argv: 'node --test',
          timeout_seconds: 0,
          approval: 'sometimes',
          max_output_bytes: -1,
          surprise_key: true,
        },
        alsobroken: { argv: [] },
      }),
    );
    assert.equal(result.verdict, 'invalid');
    assert.ok(result.errors.length >= 5, `expected several errors, got ${result.errors.length}`);
    for (const error of result.errors) {
      assert.match(error, /broken/, `every error names the command: ${error}`);
    }
  });

  test('a mistyped key is an error, never a silent default', () => {
    const result = parsePolicy(policyText({ test: command({ timeout: 300 }) }));
    assert.equal(result.verdict, 'invalid');
    assert.ok(result.errors.some((error) => error.includes('timeout')));
  });

  test('a relative cwd is rejected', () => {
    const result = parsePolicy(policyText({ test: command({ cwd: 'relative/dir' }) }));
    assert.equal(result.verdict, 'invalid');
    assert.ok(result.errors.some((error) => error.includes('cwd')));
  });

  test('argv violations are rejected', () => {
    const bad = ['node --test', [], ['node', 42], ['node', ''], ['node', null], ['a\0b']];
    for (const argv of bad) {
      const result = parsePolicy(policyText({ test: command({ argv }) }));
      assert.equal(result.verdict, 'invalid', `argv ${JSON.stringify(argv)} must be rejected`);
    }
  });

  test('a non-object command is rejected', () => {
    for (const value of ['node --test', 42, null, ['node'], true]) {
      const result = parsePolicy(policyText({ test: value }));
      assert.equal(result.verdict, 'invalid', `${JSON.stringify(value)} must be rejected`);
    }
  });
});

describe('policy: resolveCommand is exact', () => {
  const policy = parseOrFail(policyText({ test: command(), 'git.status': command({ argv: ['git', 'status'] }) }));

  test('a declared name resolves to its command', () => {
    const result = resolveCommand(policy, 'test');
    assert.equal(result.verdict, 'ok');
    assert.deepEqual(result.command.argv, ['node', '--test']);
    assert.equal(result.command.approval, 'always');
  });

  test('an undeclared name is denied with a reason', () => {
    const result = resolveCommand(policy, 'rm');
    assert.equal(result.verdict, 'denied');
    assert.ok(result.reason.length > 0);
  });

  test('resolution never prefix-matches, case-folds or trims', () => {
    for (const name of ['tes', 'test2', 'Test', 'TEST', 'test ', ' test', 'git', 'git.', 'git.status.', 't']) {
      assert.equal(resolveCommand(policy, name).verdict, 'denied', `"${name}" must be denied`);
    }
  });

  test('non-string and empty names are denied, never thrown', () => {
    for (const name of [undefined, null, 42, {}, [], '', true]) {
      assert.equal(resolveCommand(policy, name).verdict, 'denied', String(name));
    }
  });

  // A plain object inherits from Object.prototype, so a lookup written as
  // `commands[name] !== undefined` would happily resolve `toString` to a
  // function. The declaration must be an OWN property or it does not exist.
  test('an inherited prototype key is not a declared command', () => {
    for (const name of ['toString', 'constructor', 'hasOwnProperty', 'valueOf', '__proto__']) {
      assert.equal(resolveCommand(policy, name).verdict, 'denied', name);
    }
  });

  test('an unusable policy is denied, never thrown', () => {
    for (const bad of [undefined, null, {}, { commands: null }, { commands: 'test' }, 'policy']) {
      assert.equal(resolveCommand(bad, 'test').verdict, 'denied', JSON.stringify(bad));
    }
  });
});

describe('policy: validateArgv rejects structure and accepts data', () => {
  test('an ordinary argv is accepted', () => {
    assert.equal(validateArgv(['node', '--test', 'tests/*.test.mjs']).verdict, 'ok');
  });

  // The guarantee against injection is `shell: false` at execution time (S3),
  // not character screening here. These are DATA, and rejecting them would
  // break legitimate commands while making nobody safer.
  test('shell metacharacters are inert data, so they are accepted', () => {
    const accepted = [
      ['git', 'commit', '-m', 'fix: a && b'],
      ['cmd', '/c', 'echo', 'a;b'],
      ['sh', '-c', 'echo hi | wc -l'],
      ['node', '-e', 'console.log(1)'],
      ['echo', '$(whoami)'],
      ['echo', '`id`'],
      ['echo', 'a > out.txt'],
      ['echo', '*'],
      ['echo', 'a < b'],
      ['echo', '${HOME}'],
      ['C:\\Program Files\\App\\app.exe', '--path', 'C:\\My Documents'],
      ['echo', '"quoted"', "'single'"],
      ['echo', 'line1\nline2'],
    ];
    for (const argv of accepted) {
      assert.equal(validateArgv(argv).verdict, 'ok', JSON.stringify(argv));
    }
  });

  test('a command string is rejected: argv is the only accepted shape', () => {
    const result = validateArgv('node --test');
    assert.equal(result.verdict, 'invalid');
    assert.ok(result.reason.length > 0);
  });

  test('structural violations are rejected with a reason', () => {
    const rejected = [[], ['node', 42], ['node', ''], ['node', null], ['a\0b'], null, undefined, {}, 42, true];
    for (const argv of rejected) {
      const result = validateArgv(argv);
      assert.equal(result.verdict, 'invalid', JSON.stringify(argv));
      assert.ok(result.reason.length > 0, 'has a reason');
    }
  });
});

describe('policy: fingerprintCommand is deterministic', () => {
  test('the same command always produces the same fingerprint', () => {
    const a = fingerprintCommand({ argv: ['node', '--test'], cwd: ABSOLUTE_CWD });
    const b = fingerprintCommand({ argv: ['node', '--test'], cwd: ABSOLUTE_CWD });
    assert.equal(a, b);
  });

  test('the fingerprint is 16 lowercase hex characters', () => {
    assert.match(fingerprintCommand({ argv: ['node', '--test'] }), /^[0-9a-f]{16}$/);
  });

  test('a different executable changes the fingerprint', () => {
    assert.notEqual(fingerprintCommand({ argv: ['node'] }), fingerprintCommand({ argv: ['git'] }));
  });

  test('argv order is semantic and changes the fingerprint', () => {
    assert.notEqual(
      fingerprintCommand({ argv: ['git', 'status', '--short'] }),
      fingerprintCommand({ argv: ['git', '--short', 'status'] }),
    );
  });

  test('a different cwd changes the fingerprint', () => {
    assert.notEqual(
      fingerprintCommand({ argv: ['node'], cwd: ABSOLUTE_CWD }),
      fingerprintCommand({ argv: ['node'], cwd: resolvePath('other') }),
    );
  });

  test('an omitted cwd and an explicit null agree: one identity, not two', () => {
    assert.equal(
      fingerprintCommand({ argv: ['node'] }),
      fingerprintCommand({ argv: ['node'], cwd: null }),
    );
  });
});
