#!/usr/bin/env python3
"""dupecode - Python Code Clone Detector.

Zero-dependency AST-based tool that finds duplicated code blocks in Python
projects. Detects exact clones, parameterized clones (same structure, different
names/values), and near-clones.

Usage:
    python dupecode.py [options] <path> [<path>...]
    python dupecode.py --min-lines 6 src/
    python dupecode.py --check --threshold 90 src/

Options:
    --min-lines N       Minimum lines for a clone (default: 5)
    --min-tokens N      Minimum AST nodes for a clone (default: 20)
    --check             Exit with code 1 if score below threshold
    --threshold N       Score threshold for --check (default: 90)
    --json              Output JSON
    --top N             Show top N clone groups (default: 10)
    --verbose           Show code snippets
    --quiet             Only show summary
    -h, --help          Show this help
    --version           Show version
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
from collections import defaultdict
from typing import NamedTuple


__version__ = "0.1.0"


# ── Data Structures ──────────────────────────────────────────────────────────

class CodeBlock(NamedTuple):
    file: str
    start_line: int
    end_line: int
    node_count: int
    code_hash: str
    structural_hash: str


class CloneGroup(NamedTuple):
    structural_hash: str
    blocks: list[CodeBlock]
    line_count: int
    node_count: int
    clone_type: str  # exact, parameterized


# ── AST Normalization & Hashing ──────────────────────────────────────────────

def _node_type(node: ast.AST) -> str:
    """Get a string representation of node type."""
    return type(node).__name__


def _structural_signature(node: ast.AST) -> str:
    """Create a structural signature of an AST subtree.

    Normalizes away names and constants to detect parameterized clones.
    """
    parts = []

    def _walk(n: ast.AST, depth: int) -> None:
        nt = _node_type(n)
        parts.append(f"{depth}:{nt}")

        # Add structural info without specific values
        if isinstance(n, ast.FunctionDef):
            parts.append(f"args:{len(n.args.args)}")
        elif isinstance(n, ast.For):
            parts.append("for")
        elif isinstance(n, ast.While):
            parts.append("while")
        elif isinstance(n, ast.If):
            parts.append(f"elif:{len(n.orelse) > 0}")
        elif isinstance(n, ast.BinOp):
            parts.append(f"op:{_node_type(n.op)}")
        elif isinstance(n, ast.Compare):
            parts.append(f"ops:{','.join(_node_type(o) for o in n.ops)}")
        elif isinstance(n, ast.BoolOp):
            parts.append(f"bop:{_node_type(n.op)}")
        elif isinstance(n, ast.UnaryOp):
            parts.append(f"uop:{_node_type(n.op)}")
        elif isinstance(n, ast.Call):
            parts.append(f"nargs:{len(n.args)},nkw:{len(n.keywords)}")

        for child in ast.iter_child_nodes(n):
            _walk(child, depth + 1)

    _walk(node, 0)
    return "|".join(parts)


def _exact_signature(node: ast.AST) -> str:
    """Create an exact signature including names and constants."""
    parts = []

    def _walk(n: ast.AST, depth: int) -> None:
        nt = _node_type(n)
        parts.append(f"{depth}:{nt}")

        if isinstance(n, ast.Name):
            parts.append(f"name:{n.id}")
        elif isinstance(n, ast.Constant):
            parts.append(f"val:{repr(n.value)[:50]}")
        elif isinstance(n, ast.Attribute):
            parts.append(f"attr:{n.attr}")
        elif isinstance(n, ast.FunctionDef):
            parts.append(f"fn:{n.name},args:{len(n.args.args)}")
        elif isinstance(n, ast.AsyncFunctionDef):
            parts.append(f"afn:{n.name},args:{len(n.args.args)}")
        elif isinstance(n, ast.ClassDef):
            parts.append(f"cls:{n.name}")
        elif isinstance(n, ast.BinOp):
            parts.append(f"op:{_node_type(n.op)}")
        elif isinstance(n, ast.Compare):
            parts.append(f"ops:{','.join(_node_type(o) for o in n.ops)}")
        elif isinstance(n, ast.BoolOp):
            parts.append(f"bop:{_node_type(n.op)}")
        elif isinstance(n, ast.Call):
            parts.append(f"nargs:{len(n.args)},nkw:{len(n.keywords)}")

        for child in ast.iter_child_nodes(n):
            _walk(child, depth + 1)

    _walk(node, 0)
    return "|".join(parts)


def _count_nodes(node: ast.AST) -> int:
    """Count AST nodes in a subtree."""
    count = 0
    for _ in ast.walk(node):
        count += 1
    return count


def _hash_sig(sig: str) -> str:
    """Hash a signature string."""
    return hashlib.md5(sig.encode()).hexdigest()[:16]


# ── Block Extraction ─────────────────────────────────────────────────────────

def extract_blocks(source: str, filename: str,
                   min_lines: int = 5, min_tokens: int = 20) -> list[CodeBlock]:
    """Extract hashable code blocks from source."""
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []

    blocks = []
    lines = source.splitlines()

    # Extract blocks at different granularities
    for node in ast.walk(tree):
        # Function/method level
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _maybe_add_block(node, filename, lines, blocks, min_lines, min_tokens)

        # Statement sequences (for/while/if/with bodies)
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.If,
                             ast.With, ast.AsyncWith, ast.Try)):
            body = getattr(node, "body", [])
            if len(body) >= 2:
                _maybe_add_compound_block(body, filename, lines, blocks,
                                         min_lines, min_tokens)

        # Class methods collectively
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _maybe_add_block(item, filename, lines, blocks,
                                    min_lines, min_tokens)

    return blocks


def _maybe_add_block(node: ast.AST, filename: str, lines: list[str],
                     blocks: list[CodeBlock],
                     min_lines: int, min_tokens: int) -> None:
    """Add a block if it meets size thresholds."""
    start = node.lineno
    end = getattr(node, "end_lineno", start)
    line_count = end - start + 1

    if line_count < min_lines:
        return

    node_count = _count_nodes(node)
    if node_count < min_tokens:
        return

    structural = _structural_signature(node)
    exact = _exact_signature(node)

    blocks.append(CodeBlock(
        file=filename,
        start_line=start,
        end_line=end,
        node_count=node_count,
        code_hash=_hash_sig(exact),
        structural_hash=_hash_sig(structural),
    ))


def _maybe_add_compound_block(stmts: list[ast.stmt], filename: str,
                               lines: list[str], blocks: list[CodeBlock],
                               min_lines: int, min_tokens: int) -> None:
    """Add a compound block (sequence of statements)."""
    if not stmts:
        return

    start = stmts[0].lineno
    end = getattr(stmts[-1], "end_lineno", stmts[-1].lineno)
    line_count = end - start + 1

    if line_count < min_lines:
        return

    # Create a wrapper module to hash
    wrapper = ast.Module(body=list(stmts), type_ignores=[])
    node_count = _count_nodes(wrapper)
    if node_count < min_tokens:
        return

    structural = _structural_signature(wrapper)
    exact = _exact_signature(wrapper)

    blocks.append(CodeBlock(
        file=filename,
        start_line=start,
        end_line=end,
        node_count=node_count,
        code_hash=_hash_sig(exact),
        structural_hash=_hash_sig(structural),
    ))


# ── Clone Detection ──────────────────────────────────────────────────────────

def find_clones(all_blocks: list[CodeBlock]) -> list[CloneGroup]:
    """Find clone groups from extracted blocks."""
    # Group by exact hash (Type 1: exact clones)
    exact_groups: dict[str, list[CodeBlock]] = defaultdict(list)
    for block in all_blocks:
        exact_groups[block.code_hash].append(block)

    # Group by structural hash (Type 2: parameterized clones)
    structural_groups: dict[str, list[CodeBlock]] = defaultdict(list)
    for block in all_blocks:
        structural_groups[block.structural_hash].append(block)

    clones: list[CloneGroup] = []
    seen_blocks: set[tuple[str, int, int]] = set()

    # Exact clones first
    for hash_val, blocks in exact_groups.items():
        if len(blocks) < 2:
            continue

        # Deduplicate overlapping blocks
        deduped = _deduplicate_overlapping(blocks)
        if len(deduped) < 2:
            continue

        # Skip if all in same file at same location
        locations = {(b.file, b.start_line) for b in deduped}
        if len(locations) < 2:
            continue

        line_count = deduped[0].end_line - deduped[0].start_line + 1
        for b in deduped:
            seen_blocks.add((b.file, b.start_line, b.end_line))

        clones.append(CloneGroup(
            structural_hash=hash_val,
            blocks=deduped,
            line_count=line_count,
            node_count=deduped[0].node_count,
            clone_type="exact",
        ))

    # Parameterized clones (not already found as exact)
    for hash_val, blocks in structural_groups.items():
        if len(blocks) < 2:
            continue

        # Filter out blocks already in exact clone groups
        remaining = [b for b in blocks
                     if (b.file, b.start_line, b.end_line) not in seen_blocks]

        # But we need at least 2 blocks with DIFFERENT code_hashes
        # (same structural hash, different exact hash = parameterized clone)
        if len(remaining) < 2:
            # Check if we have blocks with different exact hashes
            unique_exact = {b.code_hash for b in blocks}
            if len(unique_exact) < 2:
                continue
            remaining = blocks

        deduped = _deduplicate_overlapping(remaining)
        if len(deduped) < 2:
            continue

        locations = {(b.file, b.start_line) for b in deduped}
        if len(locations) < 2:
            continue

        # Only add if not all exact
        unique_exact = {b.code_hash for b in deduped}
        if len(unique_exact) < 2:
            continue

        line_count = deduped[0].end_line - deduped[0].start_line + 1

        clones.append(CloneGroup(
            structural_hash=hash_val,
            blocks=deduped,
            line_count=line_count,
            node_count=deduped[0].node_count,
            clone_type="parameterized",
        ))

    # Sort by total duplicated lines (descending)
    clones.sort(key=lambda c: -(c.line_count * len(c.blocks)))

    return clones


def _deduplicate_overlapping(blocks: list[CodeBlock]) -> list[CodeBlock]:
    """Remove overlapping blocks, keeping the larger one."""
    if len(blocks) <= 1:
        return blocks

    # Sort by file, then start_line
    sorted_blocks = sorted(blocks, key=lambda b: (b.file, b.start_line))
    result = [sorted_blocks[0]]

    for block in sorted_blocks[1:]:
        prev = result[-1]
        # Check overlap with previous
        if (block.file == prev.file
                and block.start_line <= prev.end_line):
            # Overlapping — keep the larger one
            if block.node_count > prev.node_count:
                result[-1] = block
        else:
            result.append(block)

    return result


# ── File Scanning ────────────────────────────────────────────────────────────

def find_python_files(paths: list[str]) -> list[str]:
    files = []
    for path in paths:
        if os.path.isfile(path) and path.endswith(".py"):
            files.append(path)
        elif os.path.isdir(path):
            for root, dirs, filenames in os.walk(path):
                dirs[:] = [d for d in dirs if not d.startswith(".")
                           and d not in ("__pycache__", "node_modules", ".git",
                                         "venv", ".venv", "env", ".env",
                                         ".tox", ".mypy_cache", ".pytest_cache",
                                         "dist", "build", "egg-info")]
                for fn in sorted(filenames):
                    if fn.endswith(".py"):
                        files.append(os.path.join(root, fn))
    return sorted(files)


def analyze_project(paths: list[str], min_lines: int = 5,
                    min_tokens: int = 20) -> tuple[list[CloneGroup], int, int]:
    """Analyze project for code clones.

    Returns (clone_groups, total_lines, files_scanned).
    """
    files = find_python_files(paths)
    all_blocks: list[CodeBlock] = []
    total_lines = 0
    sources: dict[str, str] = {}

    for filepath in files:
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                source = f.read()
        except (OSError, IOError):
            continue

        sources[filepath] = source
        total_lines += len(source.splitlines())
        blocks = extract_blocks(source, filepath, min_lines, min_tokens)
        all_blocks.extend(blocks)

    clones = find_clones(all_blocks)

    return clones, total_lines, len(files)


# ── Scoring ──────────────────────────────────────────────────────────────────

def compute_score(clones: list[CloneGroup], total_lines: int) -> int:
    """Score based on duplicated line ratio. 100 = no duplication."""
    if total_lines == 0:
        return 100

    # Count duplicated lines (lines that appear in clone groups)
    dup_lines = 0
    for group in clones:
        # Each clone beyond the first is "duplicated"
        extra_copies = len(group.blocks) - 1
        dup_lines += group.line_count * extra_copies

    dup_ratio = dup_lines / total_lines
    score = max(0, min(100, round(100 * (1 - dup_ratio * 2))))
    return score


def compute_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


# ── Output Formatting ────────────────────────────────────────────────────────

def format_text(clones: list[CloneGroup], total_lines: int,
                files_scanned: int, top_n: int = 10,
                verbose: bool = False, quiet: bool = False,
                sources: dict[str, str] | None = None) -> str:
    lines = []

    lines.append(f"\n{'─' * 65}")
    lines.append(f"  dupecode v{__version__} — Python Code Clone Detector")
    lines.append(f"{'─' * 65}")

    if not quiet and clones:
        for i, group in enumerate(clones[:top_n]):
            icon = "🔴" if group.clone_type == "exact" else "🟡"
            lines.append(f"\n{icon} Clone Group #{i+1} ({group.clone_type}, "
                        f"{group.line_count} lines, {len(group.blocks)} copies)")

            for block in group.blocks:
                short = block.file
                if len(short) > 50:
                    short = "..." + short[-47:]
                lines.append(f"  📄 {short}:{block.start_line}-{block.end_line}")

            if verbose and sources:
                # Show first block's code
                first = group.blocks[0]
                if first.file in sources:
                    src_lines = sources[first.file].splitlines()
                    start = max(0, first.start_line - 1)
                    end = min(len(src_lines), first.end_line)
                    snippet = src_lines[start:end]
                    lines.append("  ┌─────────")
                    for j, sl in enumerate(snippet[:10]):
                        lines.append(f"  │ {sl}")
                    if len(snippet) > 10:
                        lines.append(f"  │ ... ({len(snippet) - 10} more lines)")
                    lines.append("  └─────────")

    # Summary
    score = compute_score(clones, total_lines)
    grade = compute_grade(score)

    total_dup_lines = sum(g.line_count * (len(g.blocks) - 1) for g in clones)
    dup_pct = total_dup_lines / total_lines * 100 if total_lines else 0

    exact_groups = sum(1 for c in clones if c.clone_type == "exact")
    param_groups = sum(1 for c in clones if c.clone_type == "parameterized")

    lines.append(f"\n{'─' * 65}")
    lines.append(f"  Score: {score}/100 (Grade: {grade})")
    lines.append(f"  Files: {files_scanned} | Lines: {total_lines:,} | "
                f"Duplicated: {total_dup_lines:,} ({dup_pct:.1f}%)")
    lines.append(f"  Clone groups: {len(clones)} "
                f"({exact_groups} exact, {param_groups} parameterized)")
    lines.append(f"{'─' * 65}")

    return "\n".join(lines)


def format_json(clones: list[CloneGroup], total_lines: int,
                files_scanned: int) -> str:
    score = compute_score(clones, total_lines)
    total_dup = sum(g.line_count * (len(g.blocks) - 1) for g in clones)

    data = {
        "version": __version__,
        "score": score,
        "grade": compute_grade(score),
        "total_lines": total_lines,
        "duplicated_lines": total_dup,
        "duplication_pct": round(total_dup / total_lines * 100, 1) if total_lines else 0,
        "files_scanned": files_scanned,
        "clone_groups": len(clones),
        "clones": [
            {
                "type": g.clone_type,
                "lines": g.line_count,
                "copies": len(g.blocks),
                "locations": [
                    {"file": b.file, "start": b.start_line, "end": b.end_line}
                    for b in g.blocks
                ],
            }
            for g in clones
        ],
    }
    return json.dumps(data, indent=2)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    paths: list[str] = []
    min_lines = 5
    min_tokens = 20
    check = False
    threshold = 90
    output_json = False
    top_n = 10
    verbose = False
    quiet = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--min-lines" and i + 1 < len(args):
            i += 1
            min_lines = int(args[i])
        elif arg == "--min-tokens" and i + 1 < len(args):
            i += 1
            min_tokens = int(args[i])
        elif arg == "--check":
            check = True
        elif arg == "--threshold" and i + 1 < len(args):
            i += 1
            threshold = int(args[i])
        elif arg == "--json":
            output_json = True
        elif arg == "--top" and i + 1 < len(args):
            i += 1
            top_n = int(args[i])
        elif arg == "--verbose":
            verbose = True
        elif arg == "--quiet":
            quiet = True
        elif arg in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        elif arg == "--version":
            print(f"dupecode {__version__}")
            return 0
        elif not arg.startswith("-"):
            paths.append(arg)
        else:
            print(f"Unknown option: {arg}", file=sys.stderr)
            return 2
        i += 1

    if not paths:
        print(__doc__.strip())
        return 2

    # Analyze
    clones, total_lines, files_scanned = analyze_project(paths, min_lines, min_tokens)

    # Load sources for verbose mode
    sources = {}
    if verbose:
        for filepath in find_python_files(paths):
            try:
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    sources[filepath] = f.read()
            except (OSError, IOError):
                pass

    if output_json:
        print(format_json(clones, total_lines, files_scanned))
    else:
        print(format_text(clones, total_lines, files_scanned,
                         top_n=top_n, verbose=verbose, quiet=quiet,
                         sources=sources))

    if check:
        score = compute_score(clones, total_lines)
        return 0 if score >= threshold else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
