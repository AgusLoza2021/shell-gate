#!/usr/bin/env node
// The executable is a wrapper on purpose: every decision lives in `main`, and
// this file only supplies the two things `main` cannot inject for itself --
// the real process arguments and a process to exit.
import { main } from '../src/cli.mjs';

process.exitCode = await main({ argv: process.argv.slice(2) });
