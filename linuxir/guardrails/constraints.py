"""The ConstraintEnforcer — architectural, model-independent evidence-integrity guarding.

This is the single most important module in the system. Its premise: **the model never
gets the chance to spoliate evidence**, because every tool call is validated by Python
*before* any subprocess or filesystem write occurs. The guarantees here are code, not
prompt instructions — a jailbroken or hallucinating model cannot talk its way past them.

The enforcer rejects a tool call when any of the following hold:

1. **Mutation-by-name** — the tool name matches a write/delete/modify pattern
   (``write_``, ``delete_``, ``rm_``, ``dd_``, ``chmod_``, ``truncate_`` ...).
2. **Unregistered tool** — the tool is not in the read-only registry the gateway built.
3. **Path escape** — a declared path argument resolves (via ``realpath``, so ``..`` is
   neutralized) outside every ``evidence_scope`` root. Reads must stay in scope too.
4. **Unsafe shell** — the ``bash_readonly`` escape hatch is restricted to an allowlist of
   read-only binaries and rejects redirects (``>``/``>>``), in-place edits, and
   destructive flags. Anything else (``dd``, ``rm``, ``chmod``, ``truncate``, ``tee`` ...)
   is simply not on the allowlist.
5. **Write-flag** — output flags (``--output-file``, ``--output``, ``-o``, ``of=``) on
   tools like volatility are rejected outright; a read-only analysis never writes files.

On a violation it raises :class:`SpoliationViolation`; the gateway catches it, logs it to
the dedicated spoliation stream, and returns a structured "blocked" result to the model.
"""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterable, Sequence
from pathlib import Path


class SpoliationViolation(Exception):
    """Raised when a tool call would (or could) alter evidence or escape its scope."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# Tool names that imply mutation. Matched anywhere in the (lowercased) name so that both
# prefixes ("write_file") and embedded verbs ("evidence_delete") are caught.
_MUTATION_NAME_RE = re.compile(
    r"(?:^|_)(write|delete|remove|rm|unlink|modify|edit|chmod|chown|truncate|"
    r"dd|format|mkfs|wipe|shred|overwrite|create_file|move|mv|rename)(?:_|$)"
)

# Binaries the bash_readonly escape hatch may invoke. Everything destructive is simply
# absent from this set, so it is denied by default rather than by enumeration.
_READONLY_BINARIES = frozenset(
    {
        "cat", "head", "tail", "less", "more", "strings", "grep", "egrep", "fgrep",
        "zgrep", "file", "stat", "ls", "find", "awk", "gawk", "sed", "sort", "uniq",
        "wc", "cut", "tr", "xxd", "hexdump", "od", "readlink", "basename", "dirname",
        "date", "echo", "true", "sha256sum", "md5sum", "sha1sum", "b2sum",
        # forensic read tools (sleuthkit)
        "mmls", "fls", "icat", "fsstat", "istat", "blkls", "img_stat", "mactime",
    }
)

# Shell tokens that indicate a write/redirect/destructive operation.
_FORBIDDEN_SHELL_TOKENS = frozenset({">", ">>", "<>", ">|", "|&", "&>", ">&", "tee"})

# Flags that, on any tool, indicate the model is trying to write a file out.
_WRITE_FLAGS = frozenset({"--output-file", "--output", "--out", "-o", "--dump-dir", "-D"})


class ConstraintEnforcer:
    """Validates tool calls against a case's read-only evidence scope."""

    def __init__(self, evidence_scope: Sequence[Path], writable_roots: Sequence[Path] = ()):
        # Canonicalize once so containment checks are cheap and ``..``-proof.
        self.evidence_roots = tuple(Path(os.path.realpath(p)) for p in evidence_scope)
        self.writable_roots = tuple(Path(os.path.realpath(p)) for p in writable_roots)

    # -- public API ---------------------------------------------------------------

    def check(
        self,
        tool_name: str,
        tool_input: dict,
        *,
        is_registered: bool,
        path_params: Iterable[str] = (),
        command_params: Iterable[str] = (),
        arg_params: Iterable[str] = (),
    ) -> None:
        """Raise :class:`SpoliationViolation` if the call is not permitted.

        ``path_params`` name input keys holding evidence paths (containment-checked);
        ``command_params`` name keys holding a shell command (allowlist-parsed);
        ``arg_params`` name keys holding free argument lists (write-flag scanned).
        """
        name = tool_name.lower()

        # 1. Mutation by tool name — caught regardless of registration.
        if _MUTATION_NAME_RE.search(name):
            raise SpoliationViolation(
                f"tool name '{tool_name}' denotes a mutating or network-exfiltration operation; "
                "evidence is mounted read-only and may not be modified or transmitted off-system"
            )

        # 2. Only tools the gateway registered as read-only may run.
        if not is_registered:
            raise SpoliationViolation(
                f"tool '{tool_name}' is not in the read-only tool allowlist"
            )

        # 3. Declared path arguments must stay inside evidence scope.
        for key in path_params:
            for p in _as_paths(tool_input.get(key)):
                self._require_within_evidence(p, why=f"path argument '{key}'")

        # 4. Shell escape hatch — allowlist binaries, reject redirects/destructive flags.
        for key in command_params:
            self._check_command(str(tool_input.get(key, "")))

        # 5. Free argument lists — reject write flags and embedded paths that escape scope.
        for key in arg_params:
            self._check_args(tool_input.get(key) or [])

    # -- helpers ------------------------------------------------------------------

    def _require_within_evidence(self, p: Path, *, why: str) -> None:
        real = Path(os.path.realpath(p))
        if not any(_within(real, root) for root in self.evidence_roots):
            raise SpoliationViolation(
                f"{why} resolves to '{real}', which is outside the case evidence scope "
                f"{[str(r) for r in self.evidence_roots]}"
            )

    def _check_command(self, command: str) -> None:
        if not command.strip():
            raise SpoliationViolation("empty bash_readonly command")

        # Reject redirect/pipe-to-writer operators before tokenizing (shlex drops them).
        for tok in _FORBIDDEN_SHELL_TOKENS:
            if tok in command:
                raise SpoliationViolation(
                    f"shell redirection/operator '{tok}' is not permitted in a "
                    "read-only command (it could write outside the read path)"
                )

        try:
            tokens = shlex.split(command)
        except ValueError as exc:  # unbalanced quotes etc.
            raise SpoliationViolation(f"uparsable command: {exc}") from exc
        if not tokens:
            raise SpoliationViolation("empty bash_readonly command")

        binary = os.path.basename(tokens[0])
        if binary not in _READONLY_BINARIES:
            raise SpoliationViolation(
                f"binary '{binary}' is not on the read-only allowlist "
                f"(destructive tools like dd/rm/chmod/truncate/tee are denied by default)"
            )

        # In-place / destructive flags on otherwise-allowed binaries.
        for tok in tokens[1:]:
            if binary in {"sed", "gawk", "awk"} and tok in {"-i", "--in-place"}:
                raise SpoliationViolation(f"in-place edit flag '{tok}' modifies evidence")
            if tok in _WRITE_FLAGS or tok.startswith("of="):
                raise SpoliationViolation(f"write/output flag '{tok}' is not permitted")
            if binary == "find" and tok in {"-delete", "-exec", "-execdir", "-fprint"}:
                raise SpoliationViolation(
                    f"find action '{tok}' can mutate or escape evidence and is denied"
                )

        # Any absolute path argument in the command must stay in evidence scope.
        for tok in tokens[1:]:
            if tok.startswith("/"):
                self._require_within_evidence(Path(tok), why="command path argument")

    def _check_args(self, args: Iterable[str]) -> None:
        args = [str(a) for a in args]
        for i, tok in enumerate(args):
            if tok in _WRITE_FLAGS or tok.startswith("of="):
                raise SpoliationViolation(
                    f"output/write flag '{tok}' is not permitted on a read-only tool"
                )
            # An output flag's *value* (next token) pointed at evidence is doubly bad.
            if tok.startswith("/"):
                self._require_within_evidence(Path(tok), why="argument path")


def _as_paths(value: object) -> list[Path]:
    """Coerce a path-bearing input value into a list of Paths."""
    if value is None:
        return []
    if isinstance(value, (str, os.PathLike)):
        return [Path(value)]
    if isinstance(value, (list, tuple)):
        return [Path(v) for v in value if isinstance(v, (str, os.PathLike))]
    return []


def _within(child: Path, root: Path) -> bool:
    try:
        return child == root or child.is_relative_to(root)
    except ValueError:
        return False
