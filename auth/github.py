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
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response


@dataclass
class PendingAuth:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    created_at: float = field(default_factory=time.time)


class GitHubOAuthProvider:
    def __init__(self, github_client_id: str, github_client_secret: str, server_url: str):
        self.github_client_id = github_client_id
        self.github_client_secret = github_client_secret
        self.server_url = server_url.rstrip("/")

        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending_auths: dict[str, PendingAuth] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        github_state = secrets.token_urlsafe(32)
        self._pending_auths[github_state] = PendingAuth(client=client, params=params)

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

        pending = self._pending_auths.pop(github_state, None)
        if pending is None:
            return Response("Invalid or expired state", status_code=400)

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
        self._auth_codes[auth_code] = AuthorizationCode(
            code=auth_code,
            client_id=pending.client.client_id,
            scopes=pending.params.scopes or [],
            expires_at=time.time() + 300,
            code_challenge=pending.params.code_challenge,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            resource=pending.params.resource,
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
        code = self._auth_codes.get(authorization_code)
        if code and code.client_id == client.client_id and time.time() < code.expires_at:
            return code
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self._auth_codes.pop(authorization_code.code, None)

        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + 3600

        self._access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            resource=authorization_code.resource,
        )
        self._refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )

        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        token = self._refresh_tokens.get(refresh_token)
        if token and token.client_id == client.client_id:
            return token
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        self._refresh_tokens.pop(refresh_token.token, None)

        effective_scopes = scopes or refresh_token.scopes
        new_access_token = secrets.token_urlsafe(32)
        new_refresh_token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + 3600

        self._access_tokens[new_access_token] = AccessToken(
            token=new_access_token,
            client_id=client.client_id,
            scopes=effective_scopes,
            expires_at=expires_at,
        )
        self._refresh_tokens[new_refresh_token] = RefreshToken(
            token=new_refresh_token,
            client_id=client.client_id,
            scopes=effective_scopes,
        )

        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=3600,
            refresh_token=new_refresh_token,
            scope=" ".join(effective_scopes) if effective_scopes else None,
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        access_token = self._access_tokens.get(token)
        if access_token is None:
            return None
        if access_token.expires_at and time.time() > access_token.expires_at:
            self._access_tokens.pop(token, None)
            return None
        return access_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
        else:
            self._refresh_tokens.pop(token.token, None)
