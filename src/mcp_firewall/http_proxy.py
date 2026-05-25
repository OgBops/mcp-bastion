"""Streamable HTTP MCP proxy.

MCP's Streamable HTTP transport (replaced HTTP+SSE in 2025-03-26 spec) uses:

  - POST /  with JSON-RPC body for client → server messages
  - GET  /  for the SSE stream of server → client messages (optional)
  - DELETE / to terminate a session

This v0 supports POST/GET reverse proxying with policy enforcement. SSE
parsing is line-oriented (we buffer until "\\n\\n").

Headers we proxy unchanged: MCP-Protocol-Version, Mcp-Session-Id, Authorization.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

import aiohttp
from aiohttp import web

from .audit import AuditLog
from .jsonrpc import (
    ERROR_FIREWALL_APPROVAL_REQUIRED,
    ERROR_FIREWALL_DENIED,
    make_error_response,
    parse_frame,
    serialize_frame,
)
from .policy import PolicyEngine
from .types import Decision, DecisionType, Direction


PROXY_HEADERS = (
    "MCP-Protocol-Version",
    "Mcp-Session-Id",
    "Authorization",
    "Content-Type",
    "Accept",
    "Last-Event-ID",
)


class HttpProxy:
    def __init__(
        self,
        upstream_url: str,
        engine: PolicyEngine,
        audit: AuditLog,
        verbose: bool = False,
    ) -> None:
        self.upstream_url = upstream_url.rstrip("/")
        self.engine = engine
        self.audit = audit
        self.verbose = verbose
        self._session: aiohttp.ClientSession | None = None

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_route("POST", "/{tail:.*}", self._handle_post)
        app.router.add_route("GET", "/{tail:.*}", self._handle_get)
        app.router.add_route("DELETE", "/{tail:.*}", self._handle_delete)
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)
        return app

    async def _on_startup(self, _: web.Application) -> None:
        self._session = aiohttp.ClientSession()

    async def _on_cleanup(self, _: web.Application) -> None:
        if self._session is not None:
            await self._session.close()

    # ---- POST: client → server JSON-RPC ----

    async def _handle_post(self, request: web.Request) -> web.StreamResponse:
        assert self._session is not None
        body = await request.read()
        frame = parse_frame(body, Direction.CLIENT_TO_SERVER)
        decision = self.engine.evaluate(frame)
        row = self.audit.append(frame, decision)
        if self.verbose:
            self._log("POST", row.seq, frame, decision)

        if decision.type == DecisionType.DENY:
            return _json_rpc_error(frame.rpc_id, ERROR_FIREWALL_DENIED, decision.reason)
        if decision.type == DecisionType.REQUIRE_APPROVAL:
            return _json_rpc_error(
                frame.rpc_id,
                ERROR_FIREWALL_APPROVAL_REQUIRED,
                f"approval required: {decision.reason}",
            )

        outbound_body = body
        if decision.type == DecisionType.REDACT and decision.rewritten_payload is not None:
            outbound_body = serialize_frame(decision.rewritten_payload).rstrip(b"\n")

        target_url = self._target(request)
        headers = _forward_headers(request.headers)

        async with self._session.post(
            target_url, data=outbound_body, headers=headers
        ) as upstream_resp:
            response_body = await upstream_resp.read()
            # Server may answer JSON-RPC inline (single response) — re-evaluate.
            if response_body.strip():
                resp_frame = parse_frame(response_body, Direction.SERVER_TO_CLIENT)
                resp_decision = self.engine.evaluate(resp_frame)
                self.audit.append(resp_frame, resp_decision)
                if self.verbose:
                    self._log("POST<-", row.seq, resp_frame, resp_decision)
                if resp_decision.type == DecisionType.DENY:
                    return _json_rpc_error(
                        resp_frame.rpc_id,
                        ERROR_FIREWALL_DENIED,
                        resp_decision.reason,
                    )

            resp = web.Response(
                status=upstream_resp.status,
                body=response_body,
                headers={
                    k: v
                    for k, v in upstream_resp.headers.items()
                    if k.lower() in {h.lower() for h in PROXY_HEADERS}
                },
            )
            return resp

    # ---- GET: server → client SSE stream ----

    async def _handle_get(self, request: web.Request) -> web.StreamResponse:
        assert self._session is not None
        target_url = self._target(request)
        headers = _forward_headers(request.headers)

        upstream = await self._session.get(target_url, headers=headers)
        response = web.StreamResponse(
            status=upstream.status,
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() in {h.lower() for h in PROXY_HEADERS}
                or k.lower() == "content-type"
            },
        )
        await response.prepare(request)

        # SSE events are separated by blank lines; we buffer line-by-line.
        try:
            async for chunk in upstream.content.iter_chunked(4096):
                # We intercept SSE "data:" lines that look like JSON-RPC.
                # For v0 we parse line-by-line; full SSE event reassembly is v0.2.
                for line in chunk.split(b"\n"):
                    stripped = line.strip()
                    if stripped.startswith(b"data:"):
                        payload = stripped[5:].strip()
                        if payload:
                            frame = parse_frame(payload, Direction.SERVER_TO_CLIENT)
                            decision = self.engine.evaluate(frame)
                            self.audit.append(frame, decision)
                            if self.verbose:
                                self._log("SSE", -1, frame, decision)
                await response.write(chunk)
        finally:
            upstream.close()
        await response.write_eof()
        return response

    async def _handle_delete(self, request: web.Request) -> web.Response:
        assert self._session is not None
        target_url = self._target(request)
        headers = _forward_headers(request.headers)
        async with self._session.delete(target_url, headers=headers) as upstream:
            body = await upstream.read()
            return web.Response(status=upstream.status, body=body)

    # ---- helpers ----

    def _target(self, request: web.Request) -> str:
        tail = request.match_info.get("tail", "")
        path = f"/{tail}" if tail and not tail.startswith("/") else (tail or "/")
        # Append query string if present
        qs = request.query_string
        return f"{self.upstream_url}{path}" + (f"?{qs}" if qs else "")

    def _log(self, kind: str, seq: int, frame, decision) -> None:
        sys.stderr.write(
            f"[mcp-firewall {kind} #{seq}] {frame.direction.value} "
            f"{frame.method or '-'} "
            f"{('tool=' + frame.tool_name) if frame.tool_name else ''} "
            f"-> {decision.type.value}: {decision.reason}\n"
        )
        sys.stderr.flush()


def _forward_headers(headers) -> dict[str, str]:
    out: dict[str, str] = {}
    lower_allowed = {h.lower() for h in PROXY_HEADERS}
    for k, v in headers.items():
        if k.lower() in lower_allowed:
            out[k] = v
    return out


def _json_rpc_error(rpc_id: Any, code: int, message: str) -> web.Response:
    payload = make_error_response(rpc_id, code, message)
    return web.json_response(payload, status=200)


async def serve_http(
    listen_host: str,
    listen_port: int,
    proxy: HttpProxy,
) -> None:
    runner = web.AppRunner(proxy.app())
    await runner.setup()
    site = web.TCPSite(runner, listen_host, listen_port)
    await site.start()
    print(
        f"[mcp-firewall] HTTP proxy listening on {listen_host}:{listen_port} "
        f"-> {proxy.upstream_url}",
        file=sys.stderr,
    )
    # Block forever
    while True:
        await asyncio.sleep(3600)
