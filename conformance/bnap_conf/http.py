"""The HTTP carrier (draft-00 section 10): scopes, route matching, header
fields, challenges, and a small HTTP client that sends the request-target
byte for byte.
"""
import http.client
import re
import socket
import ssl
import time
import urllib.parse

from .codec import H, tagged, lp, bigsize

# ---------------------------------------------------------------- scopes (10.1)


def combine_field(values):
    """RFC 9110 section 5.3: repeated field lines joined by a comma.

    draft-00 does not fix the separator bytes; this suite uses ", ", the form
    RFC 9110 shows and most stacks produce.
    """
    return ", ".join(values)


def action_scope(method, origin, request_target, content=None, headers=()):
    """headers: (lower-case name, value as received) for each listed field, in route order."""
    target = origin + request_target
    cd = H(content) if content else b""
    hs = bigsize(len(headers)) + b"".join(lp(n.encode()) + lp(v.encode()) for n, v in headers)
    return tagged("bnap/scope/http", lp(method.encode()) + lp(target.encode()) + lp(cd) + hs)


def route_scope(origin, route_id):
    return tagged("bnap/route/http", lp(origin.encode()) + lp(route_id.encode()))


def listed_headers(names, request_headers):
    """Build the (name, value) list for the route's listed fields.

    request_headers: list of (name, value) as sent; absent fields get "".
    """
    out = []
    for n in names:
        vals = [v for k, v in request_headers if k.lower() == n]
        out.append((n, combine_field(vals) if vals else ""))
    return out


def route_matches(match, method, request_target):
    """9.1: a method, one space and a path; the path compares with the request
    path without its query; a path ending in /* matches every path below it."""
    try:
        m, path = match.split(" ", 1)
    except ValueError:
        return False
    if m != method:
        return False
    req_path = request_target.split("?", 1)[0]
    if path.endswith("/*"):
        return req_path.startswith(path[:-1])
    return req_path == path


def concrete_target(match, leaf="conformance-probe"):
    """A request-target that matches a route's match pattern."""
    path = match.split(" ", 1)[1]
    if path.endswith("/*"):
        return path[:-1] + leaf
    return path

# ---------------------------------------------------------------- challenges (RFC 9110 11.6.1)


_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_TOKEN68 = re.compile(r"[A-Za-z0-9._~+/-]+=*")


class Challenge:
    def __init__(self, scheme):
        self.scheme = scheme
        self.params = {}
        self.token68 = None
        self.raw = ""

    def __repr__(self):
        return f"Challenge({self.scheme}, {self.params})"


def _skip_ows(s, i):
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _quoted(s, i):
    assert s[i] == '"'
    i += 1
    out = []
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise ValueError("unterminated quoted-string")


def parse_challenges(value):
    """Parse one WWW-Authenticate field value into a list of Challenge."""
    s, i, out = value, 0, []
    while True:
        while i < len(s) and s[i] in " \t,":
            i += 1
        if i >= len(s):
            break
        start = i
        m = _TOKEN.match(s, i)
        if not m:
            raise ValueError("bad challenge at " + str(i))
        ch = Challenge(m.group(0))
        i = m.end()
        j = _skip_ows(s, i)
        m68 = _TOKEN68.match(s, j) if j > i else None
        if m68:
            k = _skip_ows(s, m68.end())
            if (k >= len(s) or s[k] == ",") and not _is_param_start(s, j):
                ch.token68 = m68.group(0)
                i = k
                ch.raw = s[start:i].strip()
                out.append(ch)
                continue
        i = j
        while i < len(s):
            if not _is_param_start(s, i):
                break
            pm = _TOKEN.match(s, i)
            name = pm.group(0).lower()
            i = _skip_ows(s, pm.end()) + 1
            i = _skip_ows(s, i)
            if i < len(s) and s[i] == '"':
                val, i = _quoted(s, i)
            else:
                vm = _TOKEN.match(s, i)
                if not vm:
                    raise ValueError("bad auth-param value")
                val, i = vm.group(0), vm.end()
            ch.params[name] = val
            i = _skip_ows(s, i)
            if i < len(s) and s[i] == ",":
                k = _skip_ows(s, i + 1)
                if _is_param_start(s, k):
                    i = k
                    continue
                break
        ch.raw = s[start:i].strip().rstrip(",")
        out.append(ch)
    return out


def _is_param_start(s, i):
    m = _TOKEN.match(s, i)
    if not m:
        return False
    k = _skip_ows(s, m.end())
    return k < len(s) and s[k] == "=" and not (k + 1 < len(s) and s[k + 1] == "=")


def all_challenges(header_values):
    out = []
    for v in header_values:
        out.extend(parse_challenges(v))
    return out

# ---------------------------------------------------------------- SSE


def parse_sse(body):
    """Return a list of (event name, data) from a text/event-stream body."""
    text = body.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    events = []
    for block in text.split("\n\n"):
        name, data = "message", []
        seen = False
        for line in block.split("\n"):
            if not line or line.startswith(":"):
                continue
            seen = True
            k, _, v = line.partition(":")
            v = v[1:] if v.startswith(" ") else v
            if k == "event":
                name = v
            elif k == "data":
                data.append(v)
        if seen:
            events.append((name, "\n".join(data)))
    return events

# ---------------------------------------------------------------- client


class HttpResult:
    def __init__(self, status, reason, headers, body, elapsed):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body
        self.elapsed = elapsed

    def header(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def headers_all(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def __repr__(self):
        return f"HttpResult({self.status})"


class HttpTransportError(Exception):
    pass


def http_request(base_url, method, request_target, body=None, headers=(), timeout=20.0, insecure=False):
    """Send one request on a fresh connection; the request-target goes out as given."""
    u = urllib.parse.urlsplit(base_url)
    host = u.hostname
    port = u.port
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=ctx)
    elif u.scheme == "http":
        conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
    else:
        raise HttpTransportError("unsupported scheme " + u.scheme)
    t0 = time.monotonic()
    sent = {k.lower() for k, _ in headers}
    try:
        # A Host field among headers replaces the one http.client would add; TLS SNI still names base_url.
        conn.putrequest(method, request_target, skip_host="host" in sent, skip_accept_encoding=True)
        for k, v in headers:
            conn.putheader(k, v)
        if body is not None and "content-length" not in sent:
            conn.putheader("Content-Length", str(len(body)))
        if "connection" not in sent:
            conn.putheader("Connection", "close")
        conn.endheaders(body if body is not None else None)
        resp = conn.getresponse()
        data = resp.read()
        return HttpResult(resp.status, resp.reason, list(resp.getheaders()), data, time.monotonic() - t0)
    except (OSError, http.client.HTTPException, socket.timeout, ssl.SSLError) as e:
        raise HttpTransportError(f"{type(e).__name__}: {e}") from None
    finally:
        conn.close()
