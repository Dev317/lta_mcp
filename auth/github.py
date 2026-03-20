import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from redis.asyncio import Redis
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

# TTLs in seconds
_TTL_PENDING_AUTH = 600    # 10 min
_TTL_AUTH_CODE = 300       # 5 min
_TTL_ACCESS_TOKEN = 3600   # 1 hour
_TTL_CLIENT = 0            # no expiry


def _key(prefix: str, value: str) -> str:
    return f"mcp:{prefix}:{value}"


@dataclass
class PendingAuth:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    created_at: float = field(default_factory=time.time)


class GitHubOAuthProvider:
    def __init__(self, github_client_id: str, github_client_secret: str, server_url: str, redis: Redis):
        self.github_client_id = github_client_id
        self.github_client_secret = github_client_secret
        self.server_url = server_url.rstrip("/")
        self._redis = redis

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def _dump(self, obj) -> str:
        if hasattr(obj, "model_dump"):
            return obj.model_json_schema and obj.model_dump_json()
        return json.dumps(obj)

    def _client_dump(self, client: OAuthClientInformationFull) -> str:
        return client.model_dump_json()

    def _client_load(self, raw: str) -> OAuthClientInformationFull:
        return OAuthClientInformationFull.model_validate_json(raw)

    def _pending_dump(self, pending: PendingAuth) -> str:
        return json.dumps({
            "client": json.loads(pending.client.model_dump_json()),
            "params": json.loads(pending.params.model_dump_json()),
            "created_at": pending.created_at,
        })

    def _pending_load(self, raw: str) -> PendingAuth:
        data = json.loads(raw)
        return PendingAuth(
            client=OAuthClientInformationFull.model_validate(data["client"]),
            params=AuthorizationParams.model_validate(data["params"]),
            created_at=data["created_at"],
        )

    def _auth_code_dump(self, code: AuthorizationCode) -> str:
        return code.model_dump_json()

    def _auth_code_load(self, raw: str) -> AuthorizationCode:
        return AuthorizationCode.model_validate_json(raw)

    def _access_token_dump(self, token: AccessToken) -> str:
        return token.model_dump_json()

    def _access_token_load(self, raw: str) -> AccessToken:
        return AccessToken.model_validate_json(raw)

    def _refresh_token_dump(self, token: RefreshToken) -> str:
        return token.model_dump_json()

    def _refresh_token_load(self, raw: str) -> RefreshToken:
        return RefreshToken.model_validate_json(raw)

    # ------------------------------------------------------------------
    # OAuthServerProvider interface
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = await self._redis.get(_key("client", client_id))
        return self._client_load(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        await self._redis.set(_key("client", client_info.client_id), self._client_dump(client_info))

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        github_state = secrets.token_urlsafe(32)
        pending = PendingAuth(client=client, params=params)
        await self._redis.set(
            _key("pending", github_state),
            self._pending_dump(pending),
            ex=_TTL_PENDING_AUTH,
        )

        callback_url = f"{self.server_url}/github/callback"
        return (
            "https://github.com/login/oauth/authorize?"
            + urllib.parse.urlencode(
                {
                    "client_id": self.github_client_id,
                    "redirect_uri": callback_url,
                    "scope": "read:user",
                    "state": github_state,
                }
            )
        )

    async def handle_github_callback(self, request: Request) -> Response:
        code = request.query_params.get("code")
        github_state = request.query_params.get("state")

        if not code or not github_state:
            return Response("Missing code or state", status_code=400)

        raw = await self._redis.getdel(_key("pending", github_state))
        if raw is None:
            return Response("Invalid or expired state", status_code=400)

        pending = self._pending_load(raw)

        async with httpx.AsyncClient() as http_client:
            resp = await http_client.post(
                "https://github.com/login/oauth/access_token",
                data={
                    "client_id": self.github_client_id,
                    "client_secret": self.github_client_secret,
                    "code": code,
                    "redirect_uri": f"{self.server_url}/github/callback",
                },
                headers={"Accept": "application/json"},
            )

        if resp.status_code != 200:
            return Response("GitHub OAuth exchange failed", status_code=502)

        github_data = resp.json()
        if "error" in github_data:
            description = github_data.get("error_description", github_data["error"])
            return Response(f"GitHub OAuth error: {description}", status_code=400)

        auth_code = secrets.token_urlsafe(32)
        code_obj = AuthorizationCode(
            code=auth_code,
            client_id=pending.client.client_id,
            scopes=pending.params.scopes or [],
            expires_at=time.time() + _TTL_AUTH_CODE,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=pending.params.resource,
        )
        await self._redis.set(
            _key("auth_code", auth_code),
            self._auth_code_dump(code_obj),
            ex=_TTL_AUTH_CODE,
        )

        redirect_uri = str(pending.params.redirect_uri)
        qs = urllib.parse.urlencode(
            {k: v for k, v in {"code": auth_code, "state": pending.params.state}.items() if v is not None}
        )
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(url=f"{redirect_uri}{separator}{qs}", status_code=302)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        raw = await self._redis.get(_key("auth_code", authorization_code))
        if raw is None:
            return None
        code = self._auth_code_load(raw)
        if code.client_id != client.client_id or time.time() >= code.expires_at:
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        await self._redis.delete(_key("auth_code", authorization_code.code))

        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + _TTL_ACCESS_TOKEN

        access_token_obj = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            resource=authorization_code.resource,
        )
        refresh_token_obj = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )
        await self._redis.set(
            _key("access_token", access_token),
            self._access_token_dump(access_token_obj),
            ex=_TTL_ACCESS_TOKEN,
        )
        await self._redis.set(
            _key("refresh_token", refresh_token),
            self._refresh_token_dump(refresh_token_obj),
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=_TTL_ACCESS_TOKEN,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        raw = await self._redis.get(_key("refresh_token", refresh_token))
        if raw is None:
            return None
        token = self._refresh_token_load(raw)
        return token if token.client_id == client.client_id else None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        await self._redis.delete(_key("refresh_token", refresh_token.token))

        effective_scopes = scopes or refresh_token.scopes
        new_access_token = secrets.token_urlsafe(32)
        new_refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + _TTL_ACCESS_TOKEN

        access_token_obj = AccessToken(
            token=new_access_token,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=expires_at,
        )
        refresh_token_obj = RefreshToken(
            token=new_refresh_token,
            client_id=client.client_id,
            scopes=effective_scopes,
        )
        await self._redis.set(
            _key("access_token", new_access_token),
            self._access_token_dump(access_token_obj),
            ex=_TTL_ACCESS_TOKEN,
        )
        await self._redis.set(
            _key("refresh_token", new_refresh_token),
            self._refresh_token_dump(refresh_token_obj),
        )

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=_TTL_ACCESS_TOKEN,
            refresh_token=new_refresh_token,
            scope=" ".join(effective_scopes) if effective_scopes else None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        raw = await self._redis.get(_key("access_token", token))
        if raw is None:
            return None
        access_token = self._access_token_load(raw)
        if access_token.expires_at and time.time() > access_token.expires_at:
            await self._redis.delete(_key("access_token", token))
            return None
        return access_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            await self._redis.delete(_key("access_token", token.token))
        else:
            await self._redis.delete(_key("refresh_token", token.token))
