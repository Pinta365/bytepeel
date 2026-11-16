# Evals

Cases that ask an agent to decode or edit encoded data, graded on the exact
answer. Run with `claude plugin eval`, which runs each case with the plugin
and without it (a no-plugin baseline), so the score difference is what the
plugin adds.

The cases are generated: `make_cases.py` writes every case directory and
computes each expected answer with the Python standard library, not with
bytepeel. To change a case, edit the script and run it again:

```sh
python3 plugins/bytepeel/evals/make_cases.py
```

Small cases are tens of bytes. Cases tagged `large` are hundreds of bytes to a
few KB, like real payloads.

## Running

The plugin's MCP server (`npx -y bytepeel mcp`, the published package) has to
be started for real, and its tools granted:

```sh
# Agents without code execution (the main comparison)
claude plugin eval plugins/bytepeel --runs 2 --model claude-haiku-5-5 \
  --allow-real-servers --allow-tools 'mcp__plugin_bytepeel_bytepeel__*'

# Agents that can also run sandboxed shell commands (Python, base64, openssl)
claude plugin eval plugins/bytepeel --runs 2 --model claude-haiku-5-5 \
  --allow-real-servers --allow-tools Bash 'mcp__plugin_bytepeel_bytepeel__*'
```

Add `--tag large` or `--case <glob>` to run a subset, `--keep-temp` to keep
the transcripts, and `--json out.json` for per-run results. `used-bytepeel` is
an unscored indicator of whether the run called bytepeel's tool. Results are
written to `results/` (ignored by git).
