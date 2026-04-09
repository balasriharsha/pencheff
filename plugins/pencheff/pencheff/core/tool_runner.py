"""Safe subprocess execution for system tools — no shell=True."""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass


@dataclass
class ToolResult:
    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        return self.returncode == 0


def tool_available(name: str) -> bool:
    """Check if a system tool is available on PATH."""
    return shutil.which(name) is not None


async def run_tool(
    args: list[str],
    timeout: float = 60.0,
    stdin_data: str | None = None,
) -> ToolResult:
    """Run a system tool safely with array args (no shell injection)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
        return ToolResult(
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
            returncode=proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        proc.kill()
        return ToolResult(stdout="", stderr="Timeout exceeded", returncode=-1)
    except FileNotFoundError:
        return ToolResult(stdout="", stderr=f"Tool not found: {args[0]}", returncode=-1)
