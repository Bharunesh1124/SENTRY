# Andrej Karpathy Coding Guidelines

Adopted from `forrestchang/andrej-karpathy-skills` (`multica-ai`).

These core disciplines govern all engineering and coding actions in this workspace:

---

## 1. Think Before Coding
* **Never assume silently:** If requirements, file paths, or commands are ambiguous, surface the uncertainty and ask immediately instead of guessing.
* **Surface tradeoffs:** Explain *why* a particular design or library was chosen over alternatives.
* **Never hide confusion:** If something unexpected occurs (a command fails, an import is missing), report it directly.

## 2. Simplicity First
* **Minimum code that solves the problem:** Write the cleanest, most concise implementation possible.
* **Zero speculative code:** Do not add helper functions, premature abstractions, hypothetical extensibility hooks, or features that were not explicitly requested.
* **Single responsibility:** Keep modules focused, readable, and small.

## 3. Surgical Changes
* **Touch only what you must:** Edit only the exact lines and files directly involved in the current task.
* **No collateral damage:** Do not reformat unrelated code, reorder imports, or "improve" code style in untouched sections.
* **Clean up your mess:** Remove scratch files, temporary logs, or test artifacts once verification is complete.

## 4. Goal-Driven Execution
* **Define clear success criteria:** Before writing code, know exactly what "done" looks like (e.g., CLI command outputs expected table, exit code is 0, test passes).
* **Loop until verified:** Never declare a task complete without running and proving the code works. Verify by executing commands and tests.
