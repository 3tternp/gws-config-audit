"""Tiny Google REST client: read-only GETs, paging by nextPageToken, retry on throttling."""
from __future__ import annotations

import time


class ApiError(Exception):
    def __init__(self, status, reason="", message=""):
        super().__init__(f"HTTP {status} {reason}: {message}"[:300])
        self.status, self.reason, self.message = status, reason, message

    @property
    def denied(self):
        """Missing scope, missing admin privilege, or the API is not enabled in the Cloud project."""
        return self.status in (401, 403)


class Api:
    def __init__(self, session, sleep=time.sleep):
        self.http = session                 # e.g. google.auth.transport.requests.AuthorizedSession
        self._sleep = sleep

    def _request(self, url, params):
        for attempt in range(4):
            r = self.http.get(url, params=params, timeout=60)
            if r.status_code in (429, 500, 503) and attempt < 3:
                self._sleep(min(int(r.headers.get("Retry-After", 2 ** attempt)), 30))
                continue
            return r
        return r

    @staticmethod
    def _check(r):
        if r.status_code >= 400:
            try:
                e = r.json().get("error", {})
                if isinstance(e, str):
                    e = {"message": e}
            except Exception:
                e = {}
            reason = e.get("status") or ((e.get("errors") or [{}])[0].get("reason")) or ""
            raise ApiError(r.status_code, reason, e.get("message", r.text[:150]))

    def get(self, url, params=None):
        r = self._request(url, params)
        self._check(r)
        return r.json() if r.content else {}

    def get_all(self, url, key, params=None, limit=2000):
        out, p = [], dict(params or {})
        while len(out) < limit:
            data = self.get(url, p)
            out.extend(data.get(key, []))
            token = data.get("nextPageToken")
            if not token:
                break
            p["pageToken"] = token
        return out[:limit]
