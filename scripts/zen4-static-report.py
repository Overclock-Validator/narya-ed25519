#!/usr/bin/env python3
"""Summarize stack-shaped instructions in a release benchmark binary.

This is deliberately static generated-code evidence.  It does not claim that
an SP-relative instruction executes, nor that every such instruction is a
compiler spill.  Runtime stack traffic still requires sampled/PMU evidence.
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import subprocess
import sys
from pathlib import Path


NM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\S)\s+(.+?)\s*$"
)
FUNCTION_HEADER = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
INSTRUCTION = re.compile(r"^\s*[0-9a-fA-F]+:\s*(.*?)\s*$")
SUB_RSP = re.compile(
    r"\bsub[qwl]?\s+\$(0x[0-9a-fA-F]+|[0-9]+)\s*,\s*%rsp\b"
)
ADD_RSP = re.compile(
    r"\badd[qwl]?\s+\$(-?(?:0x[0-9a-fA-F]+|[0-9]+))\s*,\s*%rsp\b"
)
VECTOR_REGISTER = re.compile(r"%[xyz]mm[0-9]+\b", re.IGNORECASE)


@dataclasses.dataclass
class FunctionEvidence:
    binary: str
    symbol: str
    address: int
    text_size: int | None
    instruction_count: int = 0
    rsp_frame_reservation_bytes: int = 0
    rsp_memory_operand_instructions: int = 0
    rsp_data_memory_instructions: int = 0
    rsp_address_only_instructions: int = 0
    rsp_vector_memory_instructions: int = 0
    push_instructions: int = 0
    pop_instructions: int = 0

    def observe(self, instruction: str) -> None:
        self.instruction_count += 1
        mnemonic = instruction.split(None, 1)[0].lower() if instruction else ""

        if self.rsp_frame_reservation_bytes == 0:
            subtract = SUB_RSP.search(instruction)
            addition = ADD_RSP.search(instruction)
            if subtract:
                self.rsp_frame_reservation_bytes = int(subtract.group(1), 0)
            elif addition:
                immediate = int(addition.group(1), 0)
                if immediate < 0:
                    self.rsp_frame_reservation_bytes = -immediate
                elif immediate >= 1 << 63:
                    # GNU objdump may render a signed immediate as its
                    # sign-extended 64-bit hexadecimal representation.
                    self.rsp_frame_reservation_bytes = (1 << 64) - immediate

        if mnemonic.startswith("push"):
            self.push_instructions += 1
        elif mnemonic.startswith("pop"):
            self.pop_instructions += 1

        if "(%rsp)" not in instruction:
            return
        self.rsp_memory_operand_instructions += 1
        if mnemonic.startswith("lea"):
            self.rsp_address_only_instructions += 1
            return
        self.rsp_data_memory_instructions += 1
        if VECTOR_REGISTER.search(instruction):
            self.rsp_vector_memory_instructions += 1


def parse_nm(lines: list[str], pattern: re.Pattern[str]) -> list[tuple[int, int, str, str]]:
    symbols: list[tuple[int, int, str, str]] = []
    for line in lines:
        match = NM_LINE.match(line)
        if not match:
            continue
        address, size, symbol_type, symbol = match.groups()
        if pattern.search(symbol):
            symbols.append((int(address, 16), int(size, 16), symbol_type, symbol))
    return sorted(symbols, key=lambda item: (item[3], item[0], item[1], item[2]))


def analyze_objdump_lines(
    lines,
    *,
    binary: str,
    pattern: re.Pattern[str],
    sizes: dict[str, int],
    disassembly,
) -> list[FunctionEvidence]:
    records: list[FunctionEvidence] = []
    current: FunctionEvidence | None = None

    for line in lines:
        header = FUNCTION_HEADER.match(line)
        if header:
            address_hex, symbol = header.groups()
            if pattern.search(symbol):
                current = FunctionEvidence(
                    binary=binary,
                    symbol=symbol,
                    address=int(address_hex, 16),
                    text_size=sizes.get(symbol),
                )
                records.append(current)
                disassembly.write(line)
            else:
                current = None
            continue

        if current is None:
            continue
        disassembly.write(line)
        instruction = INSTRUCTION.match(line)
        if instruction and instruction.group(1):
            current.observe(instruction.group(1))

    return sorted(records, key=lambda record: (record.symbol, record.address))


def run_tool(command: list[str]) -> str:
    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return completed.stdout


def write_report(args: argparse.Namespace) -> None:
    pattern = re.compile(args.pattern)
    binary_path = Path(args.binary)
    if not binary_path.is_file():
        raise RuntimeError(f"benchmark binary does not exist: {binary_path}")

    nm_text = run_tool([args.nm, "-S", "--size-sort", str(binary_path)])
    symbols = parse_nm(nm_text.splitlines(), pattern)
    if not symbols:
        raise RuntimeError(f"no symbols match {args.pattern!r} in {binary_path}")
    sizes = {symbol: size for _, size, _, symbol in symbols}

    symbols_path = Path(args.symbols_out)
    symbols_path.write_text(
        "address_hex\tsize_bytes\ttype\tsymbol\n"
        + "".join(
            f"{address:x}\t{size}\t{symbol_type}\t{symbol}\n"
            for address, size, symbol_type, symbol in symbols
        ),
        encoding="utf-8",
    )

    environment = dict(os.environ)
    environment["LC_ALL"] = "C"
    process = subprocess.Popen(
        [args.objdump, "-d", "--no-show-raw-insn", str(binary_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    assert process.stdout is not None
    with Path(args.disassembly_out).open("w", encoding="utf-8") as disassembly:
        records = analyze_objdump_lines(
            process.stdout,
            binary=binary_path.name,
            pattern=pattern,
            sizes=sizes,
            disassembly=disassembly,
        )
    stderr = process.stderr.read() if process.stderr is not None else ""
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"{args.objdump} failed: {stderr.strip()}")
    if not records:
        raise RuntimeError(f"no disassembly matches {args.pattern!r} in {binary_path}")

    columns = (
        "binary",
        "symbol",
        "address_hex",
        "text_size_bytes",
        "instruction_count",
        "rsp_frame_reservation_bytes",
        "rsp_memory_operand_instructions",
        "rsp_data_memory_instructions",
        "rsp_address_only_instructions",
        "rsp_vector_memory_instructions",
        "push_instructions",
        "pop_instructions",
    )
    with Path(args.summary_out).open("w", encoding="utf-8") as summary:
        summary.write(
            "# STATIC GENERATED-CODE EVIDENCE ONLY; this is not runtime stack-traffic evidence.\n"
            "# rsp_frame_reservation_bytes is the first immediate downward RSP adjustment "
            "seen in the function. SP-relative data accesses include arguments/locals and "
            "are only spill/reload candidates.\n"
        )
        summary.write("\t".join(columns) + "\n")
        for record in records:
            values = (
                record.binary,
                record.symbol,
                f"{record.address:x}",
                "unknown" if record.text_size is None else str(record.text_size),
                str(record.instruction_count),
                str(record.rsp_frame_reservation_bytes),
                str(record.rsp_memory_operand_instructions),
                str(record.rsp_data_memory_instructions),
                str(record.rsp_address_only_instructions),
                str(record.rsp_vector_memory_instructions),
                str(record.push_instructions),
                str(record.pop_instructions),
            )
            summary.write("\t".join(values) + "\n")


def self_test() -> None:
    pattern = re.compile(r"candidate")
    nm_lines = [
        "0000000000401000 0000000000000040 T pkg.candidateB",
        "0000000000400000 0000000000000030 T pkg.candidateA",
        "0000000000402000 0000000000000010 T pkg.unrelated",
    ]
    symbols = parse_nm(nm_lines, pattern)
    assert [symbol for _, _, _, symbol in symbols] == [
        "pkg.candidateA",
        "pkg.candidateB",
    ]

    objdump_lines = [
        "0000000000400000 <pkg.candidateA>:\n",
        "  400000:\tpush   %rbp\n",
        "  400001:\tsub    $0x80,%rsp\n",
        "  400008:\tvmovdqu64 %zmm0,0x20(%rsp)\n",
        "  400010:\tmov    0x18(%rsp),%rax\n",
        "  400018:\tlea    0x40(%rsp),%rcx\n",
        "  400020:\tpop    %rbp\n",
        "0000000000402000 <pkg.unrelated>:\n",
        "  402000:\tret\n",
        "0000000000401000 <pkg.candidateB>:\n",
        "  401000:\tadd    $-64,%rsp\n",
        "  401004:\tret\n",
    ]
    from io import StringIO

    disassembly = StringIO()
    records = analyze_objdump_lines(
        objdump_lines,
        binary="fixture.test",
        pattern=pattern,
        sizes={"pkg.candidateA": 48, "pkg.candidateB": 64},
        disassembly=disassembly,
    )
    by_symbol = {record.symbol: record for record in records}
    first = by_symbol["pkg.candidateA"]
    assert first.rsp_frame_reservation_bytes == 128
    assert first.rsp_memory_operand_instructions == 3
    assert first.rsp_data_memory_instructions == 2
    assert first.rsp_address_only_instructions == 1
    assert first.rsp_vector_memory_instructions == 1
    assert first.push_instructions == 1
    assert first.pop_instructions == 1
    assert by_symbol["pkg.candidateB"].rsp_frame_reservation_bytes == 64
    assert "pkg.unrelated" not in disassembly.getvalue()
    print("zen4-static-report: self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary")
    parser.add_argument("--pattern")
    parser.add_argument("--symbols-out")
    parser.add_argument("--disassembly-out")
    parser.add_argument("--summary-out")
    parser.add_argument("--nm", default="nm")
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    if not args.self_test:
        missing = [
            name
            for name in (
                "binary",
                "pattern",
                "symbols_out",
                "disassembly_out",
                "summary_out",
            )
            if not getattr(args, name)
        ]
        if missing:
            parser.error("missing required arguments: " + ", ".join(missing))
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            write_report(args)
    except (OSError, RuntimeError, re.error) as error:
        print(f"zen4-static-report: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
