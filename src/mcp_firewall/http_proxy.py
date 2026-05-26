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
from urllib.parse import urlparse

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
from . import nitro_enclave
from .limits import MAX_HTTP_BODY_BYTES
from .policy import PolicyEngine, safe_tool_label
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
        # Validate upstream URL up-front: must have an http(s) scheme and a
        # host, must not be a private metadata IP. We pin scheme+netloc here
        # and rebuild target URLs from this base — never trust client paths.
        parsed = urlparse(upstream_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"upstream_url must be http(s); got '{parsed.scheme}'")
        if not parsed.netloc:
            raise ValueError("upstream_url must include a host")
        if _is_blocked_host(parsed.hostname or ""):
            raise ValueError(
                f"upstream_url host '{parsed.hostname}' is on the SSRF block list "
                "(cloud metadata / link-local). Set MCP_FIREWALL_ALLOW_PRIVATE=1 to override."
            )
        self._upstream_scheme = parsed.scheme
        self._upstream_netloc = parsed.netloc
        self._upstream_base_path = parsed.path.rstrip("/")
        self.upstream_url = f"{parsed.scheme}://{parsed.netloc}{self._upstream_base_path}"
        self.engine = engine
        self.audit = audit
        self.verbose = verbose
        self._session: aiohttp.ClientSession | None = None

    def app(self) -> web.Application:
        # client_max_size is aiohttp's request-body cap. We mirror it here so
        # POST bodies cannot OOM the proxy.
        app = web.Application(client_max_size=MAX_HTTP_BODY_BYTES)
        # Operational endpoints (must be registered before the catch-all).
        app.router.add_route("GET", "/attestation", self._handle_attestation)
        app.router.add_route("GET", "/healthz", self._handle_healthz)
        app.router.add_route("POST", "/{tail:.*}", self._handle_post)
        app.router.add_route("GET", "/{tail:.*}", self._handle_get)
        app.router.add_route("DELETE", "/{tail:.*}", self._handle_delete)
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)
        return app

    async def _handle_attestation(self, request: web.Request) -> web.Response:
        """Return a Nitro attestation document or a clear 'not attested' fallback."""
        nonce_param = request.query.get("nonce")
        nonce = nonce_param.encode("utf-8") if nonce_param else None
        report = nitro_enclave.get_attestation(nonce=nonce)
        return web.json_response(nitro_enclave.attestation_to_json(report))

    async def _handle_healthz(self, _: web.Request) -> web.Response:
        return web.json_response({"status": "ok"})

    async def _on_startup(self, _: web.Application) -> None:
        self._session = aiohttp.ClientSession()

    async def _on_cleanup(self, _: web.Application) -> None:
        if self._session is not None:
            await self._session.close()

    # ---- POST: client → server JSON-RPC ----

    async def _handle_post(self, request: web.Request) -> web.StreamResponse:
        if self._session is None:
            return _json_rpc_error(None, ERROR_FIREWALL_DENIED, "proxy not initialized")
        try:
            body = await request.read()
        except aiohttp.web.HTTPRequestEntityTooLarge:
            return _json_rpc_error(
                None, ERROR_FIREWALL_DENIED, "request body exceeds limit"
            )
        if len(body) > MAX_HTTP_BODY_BYTES:
            return _json_rpc_error(
                None, ERROR_FIREWALL_DENIED, "request body exceeds limit"
            )
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
        if self._session is None:
            return web.Response(status=503, text="proxy not initialized")
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

        # SSE events are line-oriented; lines may straddle chunk boundaries.
        # We buffer until we see a complete '\n' and only parse complete lines.
        # Buffer is bounded so a malicious upstream can't OOM us by sending a
        # never-newline-terminated stream.
        buffer = bytearray()
        try:
            async for chunk in upstream.content.iter_chunked(4096):
                buffer.extend(chunk)
                if len(buffer) > MAX_HTTP_BODY_BYTES:
                    # Drop the buffer; downstream still gets the byte stream
                    # because we already wrote the chunk.
                    buffer.clear()
                while True:
                    nl = buffer.find(b"\n")
                    if nl < 0:
                        break
                    line = bytes(buffer[:nl])
                    del buffer[: nl + 1]
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
        if self._session is None:
            return web.Response(status=503, text="proxy not initialized")
        target_url = self._target(request)
        headers = _forward_headers(request.headers)
        async with self._session.delete(target_url, headers=headers) as upstream:
            body = await upstream.read()
            return web.Response(status=upstream.status, body=body)

    # ---- helpers ----

    def _target(self, request: web.Request) -> str:
        """Build the upstream URL.

        SSRF-safe: we ALWAYS use the operator-pinned scheme+netloc; the
        client-supplied path is sanitized to defeat path-traversal escapes
        (e.g., '/../169.254.169.254/...') and host-section smuggling.
        """
        tail = request.match_info.get("tail", "") or ""
        # Reject anything that looks like an attempt to inject a netloc.
        if "://" in tail or tail.startswith("//") or tail.startswith("\\"):
            tail = ""
        # Drop any leading slashes; we'll rejoin under the operator base path.
        clean_segments: list[str] = []
        for seg in tail.split("/"):
            if seg in ("", ".", ".."):
                # Dot/empty segments are silently dropped to defeat traversal.
                continue
            clean_segments.append(seg)
        suffix = ("/" + "/".join(clean_segments)) if clean_segments else "/"
        qs = request.query_string
        # Important: never let the client choose scheme/netloc.
        return (
            f"{self._upstream_scheme}://{self._upstream_netloc}"
            f"{self._upstream_base_path}{suffix}"
            + (f"?{qs}" if qs else "")
        )

    def _log(self, kind: str, seq: int, frame, decision) -> None:
        tool_label = (
            safe_tool_label(frame.tool_name) if frame.tool_name else ""
        )
        sys.stderr.write(
            f"[mcp-firewall {kind} #{seq}] {frame.direction.value} "
            f"{frame.method or '-'} "
            f"{tool_label} "
            f"-> {decision.type.value}: {decision.reason}\n"
        )
        sys.stderr.flush()


def _is_blocked_host(host: str) -> bool:
    """SSRF block list: cloud-metadata + link-local + loopback variants.

    Set MCP_FIREWALL_ALLOW_PRIVATE=1 in the environment to bypass (e.g., for
    local dev where the upstream MCP server runs on 127.0.0.1).
    """
    import os

    if os.environ.get("MCP_FIREWALL_ALLOW_PRIVATE") == "1":
        return False
    h = host.lower().strip().strip("[]")
    blocked_exact = {
        "169.254.169.254",  # AWS / GCP / Azure cloud metadata
        "metadata.google.internal",
        "metadata.goog",
        "100.100.100.200",  # Alibaba Cloud metadata
        "0.0.0.0",
    }
    if h in blocked_exact:
        return True
    if h.startswith("169.254."):  # full link-local IPv4
        return True
    if h.startswith("fe80:") or h.startswith("fc") or h.startswith("fd"):
        # IPv6 link-local + ULA
        return True
    return False


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
