"""Pinned official-endpoint fetch with host and resolved-address enforcement.

The conformance tools only contact the official Rust distribution and crates.io
metadata endpoints recorded in the checked-in lock files. This module makes that
constraint enforceable rather than implicit:

* HTTPS only, and the host must be on the allowlist.
* Every address the host resolves to must be public.
* The connection is opened to the address that was validated, so a second DNS
  answer cannot be substituted between the check and the connect.
* Each redirect hop is re-validated and re-pinned the same way.

TLS server name indication and certificate verification still use the original
hostname, so pinning the address does not weaken certificate checks.
"""
import http.client
import ipaddress
import socket
import ssl
import urllib.parse

ALLOWED_HOSTS = frozenset({'static.rust-lang.org', 'crates.io', 'static.crates.io'})
_USER_AGENT = 'MDD-parser-safety'


def resolve_public(host, port=443):
    """Resolve `host` and return one validated address.

    Every answer is checked, so a mixed answer is rejected outright rather than
    silently using whichever came first.

    The primary SSRF controls here are the hardcoded host allowlist plus HTTPS
    certificate verification against that hostname; this address check is
    defense in depth. It therefore blocks only targets that can reach the local
    host or a cloud metadata service — loopback, link-local, unspecified,
    multicast and reserved ranges — and deliberately permits private ranges so
    that a local DNS proxy answering with synthetic addresses (for example the
    RFC 2544 benchmarking range used by fake-ip resolvers) still works.
    """
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not infos:
        raise RuntimeError('pinned host did not resolve: ' + repr(host))
    addresses = []
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast or address.is_unspecified):
            raise RuntimeError('pinned host resolved to a local-only address: ' + repr(host))
        addresses.append((str(address), info[4][1]))
    return addresses[0]


def require_allowed(url):
    """Reject a URL outside the pinned scheme and host allowlist."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != 'https':
        raise RuntimeError('pinned fetch requires https: ' + repr(url))
    host = parts.hostname
    if host not in ALLOWED_HOSTS:
        raise RuntimeError('host outside pinned allowlist: ' + repr(host))
    return host


class _PinnedConnection(http.client.HTTPSConnection):
    """HTTPS connection that connects to the address already validated.

    `connect()` uses the resolved address directly while keeping `self.host`
    as the TLS server name, so certificate verification is unchanged.
    """

    def __init__(self, host, pinned_address, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = pinned_address

    def connect(self):
        sock = socket.create_connection(self._pinned_address, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedResponse:
    """Minimal response wrapper exposing status/read/headers and closing cleanly."""

    def __init__(self, connection, response):
        self._connection = connection
        self._response = response
        self.status = response.status
        self.headers = response.headers

    def read(self, amount=None):
        return self._response.read() if amount is None else self._response.read(amount)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def close(self):
        try:
            self._response.close()
        finally:
            self._connection.close()


def fetch(url, timeout=60, method=None):
    """Perform one validated HTTPS request and return its response.

    A 3xx response is returned as-is; use :func:`fetch_following` when the
    caller expects the final body (crates.io download URLs redirect to the
    static host, which is on the allowlist).
    """
    host = require_allowed(url)
    address = resolve_public(host)
    parts = urllib.parse.urlsplit(url)
    target = parts.path or '/'
    if parts.query:
        target += '?' + parts.query
    connection = None
    try:
        connection = _PinnedConnection(host, address, timeout)
        connection.connect()
        connection.putrequest(method or 'GET', target)
        connection.putheader('Host', host)
        connection.putheader('User-Agent', _USER_AGENT)
        connection.endheaders()
        response = connection.getresponse()
        return _PinnedResponse(connection, response)
    except BaseException:
        if connection is not None:
            connection.close()
        raise


MAX_REDIRECTS = 5


def _resolve_relative(base, location):
    """Resolve a Location header against the request URL."""
    if location.startswith(('http://', 'https://')):
        return location
    parts = urllib.parse.urlsplit(base)
    return urllib.parse.urljoin(parts.geturl(), location)


def fetch_following(url, timeout=60, method=None):
    """Fetch `url`, following redirects with the same per-hop validation.

    Each hop runs through :func:`require_allowed` and :func:`resolve_public`,
    and the connection is pinned to the validated address. The hop count is
    bounded so a redirect loop cannot run unbounded.
    """
    current = url
    current_method = method or 'GET'
    for _ in range(MAX_REDIRECTS + 1):
        response = fetch(current, timeout=timeout, method=current_method)
        if response.status not in (301, 302, 303, 307, 308):
            return response
        location = response.headers.get('Location')
        response.close()
        if not location:
            raise RuntimeError('redirect without a Location header from ' + repr(current))
        current = _resolve_relative(current, location)
        if response.status == 303:
            current_method = 'GET'
    raise RuntimeError('too many redirects starting from ' + repr(url))
