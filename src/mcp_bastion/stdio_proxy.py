"""stdio MCP proxy.

Spawns the upstream MCP server as a subprocess. Bridges:

  parent_stdin  ──▶  [policy: c2s]  ──▶  child_stdin
  child_stdout  ──▶  [policy: s2c]  ──▶  parent_stdout

Both directions parse newline-delimited JSON-RPC frames. Frames that violate
policy never reach the destination — the proxy synthesizes a JSON-RPC error
response back to the client instead.
"""

from __future__ import annotations

import asyncio
import shlex
import sys

from .audit import AuditLog
from .jsonrpc import (
    ERROR_FIREWALL_APPROVAL_REQUIRED,
    ERROR_FIREWALL_DENIED,
    ERROR_FIREWALL_DRIFT_BLOCKED,
    make_error_response,
    parse_frame,
    serialize_frame,
)
from .limits import MAX_FRAME_BYTES
from .policy import PolicyEngine, safe_tool_label
from .types import Decision, DecisionType, Direction


class StdioProxy:
    """One instance per upstream MCP server invocation."""

    def __init__(
        self,
        upstream_cmd: str,
        engine: PolicyEngine,
        audit: AuditLog,
        verbose: bool = False,
    ) -> None:
        self.upstream_cmd = upstream_cmd
        self.engine = engine
        self.audit = audit
        self.verbose = verbose
        self.proc: asyncio.subprocess.Process | None = None

    async def run(self) -> int:
        argv = shlex.split(self.upstream_cmd)
        if not argv:
            raise ValueError("upstream command is empty")

        self.proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
            limit=MAX_FRAME_BYTES,
        )

        loop = asyncio.get_running_loop()

        # Wrap parent's stdio in StreamReader / StreamWriter
        parent_stdin = await _stdin_reader(loop)
        parent_stdout = sys.stdout.buffer  # raw bytes write

        c2s_task = asyncio.create_task(
            self._pump_lines(
                src=parent_stdin,
                dst_write=self._proc_stdin_write,
                direction=Direction.CLIENT_TO_SERVER,
                error_back=lambda payload: parent_stdout.write(serialize_frame(payload))
                or parent_stdout.flush(),
            )
        )
        s2c_task = asyncio.create_task(
            self._pump_lines(
                src=self.proc.stdout,
                dst_write=lambda b: (parent_stdout.write(b), parent_stdout.flush()),
                direction=Direction.SERVER_TO_CLIENT,
                error_back=None,  # server->client we never inject errors back
            )
        )

        done, pending = await asyncio.wait(
            {c2s_task, s2c_task, asyncio.create_task(self.proc.wait())},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()

        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
            except ProcessLookupError:
                pass
            await self.proc.wait()

        return self.proc.returncode or 0

    # ---- internals ----

    def _proc_stdin_write(self, data: bytes) -> None:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(data)

    async def _pump_lines(
        self,
        src: asyncio.StreamReader,
        dst_write,
        direction: Direction,
        error_back,
    ) -> None:
        while True:
            try:
                # Bounded read prevents a malicious peer from flooding a single
                # line and OOMing the proxy. asyncio.StreamReader raises
                # LimitOverrunError on overflow; we drain the rest of the
                # offending line + drop it.
                line = await src.readuntil(b"\n")
            except asyncio.IncompleteReadError as e:
                # EOF reached. Forward any partial buffer if non-empty.
                line = e.partial
                if not line:
                    return
            except asyncio.LimitOverrunError:
                # Drain and drop the oversized frame; never forward it.
                await self._drain_oversized(src)
                self._record_oversized(direction)
                continue
            if not line:
                return
            if len(line) > MAX_FRAME_BYTES:
                self._record_oversized(direction)
                continue
            # Skip pure whitespace lines (some stdio servers emit blank framing)
            if not line.strip():
                if dst_write:
                    dst_write(line)
                continue

            frame = parse_frame(line, direction)
            decision = self.engine.evaluate(frame)
            row = self.audit.append(frame, decision)

            if self.verbose:
                self._log_decision(row.seq, frame, decision)

            if decision.type == DecisionType.DENY:
                if error_back is not None:
                    code, msg = self._deny_error(decision)
                    error_back(make_error_response(frame.rpc_id, code, msg))
                # else: server->client deny is just dropped + audited
                continue

            if decision.type == DecisionType.REQUIRE_APPROVAL:
                if error_back is not None:
                    error_back(
                        make_error_response(
                            frame.rpc_id,
                            ERROR_FIREWALL_APPROVAL_REQUIRED,
                            f"approval required: {decision.reason}",
                        )
                    )
                continue

            if decision.type == DecisionType.REDACT and decision.rewritten_payload is not None:
                if dst_write:
                    dst_write(serialize_frame(decision.rewritten_payload))
                continue

            # ALLOW (or response to a denied call) — forward verbatim.
            if dst_write:
                dst_write(line)

    async def _drain_oversized(self, src: asyncio.StreamReader) -> None:
        """Read and discard bytes until we hit a newline or EOF, in MAX_FRAME_BYTES
        chunks, so an attacker can't keep us reading forever."""
        drained = 0
        while drained < 16 * MAX_FRAME_BYTES:
            try:
                chunk = await src.read(MAX_FRAME_BYTES)
            except Exception:
                return
            if not chunk:
                return
            drained += len(chunk)
            if b"\n" in chunk:
                return

    def _record_oversized(self, direction: Direction) -> None:
        sys.stderr.write(
            f"[mcp-bastion] dropped oversized frame from {direction.value} "
            f"(>{MAX_FRAME_BYTES} bytes)\n"
        )
        sys.stderr.flush()

    def _deny_error(self, decision: Decision) -> tuple[int, str]:
        if decision.matched_rule == "tool_description_pinning":
            return (
                ERROR_FIREWALL_DRIFT_BLOCKED,
                f"blocked by tool description drift: {decision.reason}",
            )
        return (ERROR_FIREWALL_DENIED, f"denied by mcp-bastion: {decision.reason}")

    def _log_decision(self, seq: int, frame, decision) -> None:
        # We deliberately log only the safe hashed label, never the raw
        # tool name, so a tool with a secret-bearing name never appears in
        # stderr (which may be captured by a logging system).
        tool_label = (
            safe_tool_label(frame.tool_name) if frame.tool_name else ""
        )
        sys.stderr.write(
            f"[mcp-bastion #{seq}] {frame.direction.value} "
            f"{frame.method or '-'} "
            f"{tool_label} "
            f"-> {decision.type.value}: {decision.reason}\n"
        )
        sys.stderr.flush()


async def _stdin_reader(loop: asyncio.AbstractEventLoop) -> asyncio.StreamReader:
    # Pin the StreamReader buffer to our explicit MAX_FRAME_BYTES so that
    # readuntil() raises LimitOverrunError instead of consuming unbounded RAM.
    reader = asyncio.StreamReader(limit=MAX_FRAME_BYTES, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    return reader
