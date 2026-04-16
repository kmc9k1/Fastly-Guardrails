from __future__ import annotations

import re
from pathlib import Path

from .models import Block, Document
from .utils import relative_path

HCL_START_RE = re.compile(
    r'^\s*(resource|module|data|variable|locals|provider|terraform)'
    r'(?:\s+"([^"]+)")?(?:\s+"([^"]+)")?\s*\{'
)
VCL_SUB_RE = re.compile(r'^\s*sub\s+([A-Za-z0-9_]+)\s*\{')


class ParsedRepo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.documents: list[Document] = []
        self.blocks: list[Block] = []


def collect_documents(root: str) -> ParsedRepo:
    base = Path(root).resolve()
    parsed = ParsedRepo(base)
    skip_dirs = {".git", ".terraform", ".venv", "venv", "node_modules", "__pycache__"}

    for path in base.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in {".tf", ".vcl"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = relative_path(path, base)
        kind = "terraform" if suffix == ".tf" else "vcl"
        doc = Document(path=rel, kind=kind, text=text, lines=text.splitlines())
        parsed.documents.append(doc)
        parsed.blocks.extend(parse_blocks(doc))
    return parsed


def parse_blocks(doc: Document) -> list[Block]:
    if doc.kind == "terraform":
        return parse_hcl_blocks(doc)
    if doc.kind == "vcl":
        return parse_vcl_blocks(doc)
    return []


def parse_hcl_blocks(doc: Document) -> list[Block]:
    blocks: list[Block] = []
    lines = doc.lines
    i = 0
    while i < len(lines):
        match = HCL_START_RE.match(lines[i])
        if not match:
            i += 1
            continue
        block_type = match.group(1)
        first = match.group(2) or ""
        second = match.group(3) or ""
        if block_type == "resource":
            name = f"{first}.{second}" if second else first
        elif block_type == "data":
            name = f"{first}.{second}" if second else first
        else:
            name = first or block_type

        brace_depth = lines[i].count("{") - lines[i].count("}")
        start = i
        j = i
        while j + 1 < len(lines) and brace_depth > 0:
            j += 1
            brace_depth += lines[j].count("{") - lines[j].count("}")
        text = "\n".join(lines[start : j + 1])
        blocks.append(
            Block(
                file_path=doc.path,
                kind="terraform",
                block_type=block_type,
                name=name,
                start_line=start + 1,
                end_line=j + 1,
                text=text,
                metadata={"raw_type": first, "raw_name": second},
            )
        )
        i = j + 1
    return blocks


def parse_vcl_blocks(doc: Document) -> list[Block]:
    blocks: list[Block] = [
        Block(
            file_path=doc.path,
            kind="vcl",
            block_type="file",
            name=Path(doc.path).name,
            start_line=1,
            end_line=max(1, len(doc.lines)),
            text=doc.text,
            metadata={},
        )
    ]
    lines = doc.lines
    i = 0
    while i < len(lines):
        match = VCL_SUB_RE.match(lines[i])
        if not match:
            i += 1
            continue
        name = match.group(1)
        brace_depth = lines[i].count("{") - lines[i].count("}")
        start = i
        j = i
        while j + 1 < len(lines) and brace_depth > 0:
            j += 1
            brace_depth += lines[j].count("{") - lines[j].count("}")
        text = "\n".join(lines[start : j + 1])
        blocks.append(
            Block(
                file_path=doc.path,
                kind="vcl",
                block_type="sub",
                name=name,
                start_line=start + 1,
                end_line=j + 1,
                text=text,
                metadata={},
            )
        )
        i = j + 1
    return blocks
