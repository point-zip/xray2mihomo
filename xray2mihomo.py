"""Convert Xray (jsonc) config outbounds to a Mihomo proxies fragment.

Usage:
    python xray2mihomo.py input.jsonc [-o output.yaml]

Supports: vless + xhttp + reality, vless + xhttp + tls, vless + ws + tls.
freedom/blackhole outbounds are skipped.
"""
import json
import re
import sys
from urllib.parse import parse_qsl, unquote

PROXY_KEY_ORDER = [
    "name", "type", "server", "port", "uuid", "udp", "tls", "network",
    "alpn", "reality-opts", "servername", "client-fingerprint", "encryption",
    "xhttp-opts", "ws-opts",
]

NETWORK_OPTS_ORDER = {
    "xhttp": ["path", "host", "mode"],
    "ws": ["path", "host"],
}

REALITY_OPTS_ORDER = ["public-key", "short-id"]

FORCE_QUOTE_KEYS = {"name", "path", "mode"}

_PLAIN_UNSAFE = re.compile(r'^[\-?:\{\}\[\]"\'#!|&*%@`~,]|[:#]\s|^$|^(true|false|null|yes|no|on|off|~)$', re.IGNORECASE)
_NUMBER_LIKE = re.compile(r'^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$')


class ConversionError(Exception):
    pass


def strip_jsonc(text):
    """Remove // and /* */ comments while preserving string contents."""
    out = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\":
                i += 1
                if i < n:
                    out.append(text[i])
            elif c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def fmt_value(value):
    """Format a leaf value as YAML, quoting only when needed."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if _PLAIN_UNSAFE.match(value) or _NUMBER_LIKE.match(value):
        return json.dumps(value)
    return value


def emit_leaf(key, value):
    if isinstance(value, list):
        items = ", ".join(fmt_value(v) for v in value)
        return "%s: [%s]\n" % (key, items)
    text = fmt_value(value)
    if key in FORCE_QUOTE_KEYS and isinstance(value, str):
        text = json.dumps(value)
    return "%s: %s\n" % (key, text)


def emit_block(prefix, key, value):
    """Render a top-level proxy key; nested dicts get 4-space children."""
    if isinstance(value, dict):
        out = ["%s%s:\n" % (prefix, key)]
        for k in value:
            out.append("    " + emit_leaf(k, value[k]))
        return "".join(out)
    return prefix + emit_leaf(key, value)


def emit_proxies(proxies):
    """Render the proxy list as a YAML fragment (without the proxies: header)."""
    out = []
    for proxy in proxies:
        first = True
        for key in PROXY_KEY_ORDER:
            if key not in proxy:
                continue
            prefix = "- " if first else "  "
            out.append(emit_block(prefix, key, proxy[key]))
            first = False
    return "".join(out)


def convert_vless(outbound):
    tag = outbound.get("tag", "(untagged)")
    stream = outbound.get("streamSettings") or {}
    network = stream.get("network")
    security = stream.get("security")

    if network not in ("xhttp", "ws"):
        raise ConversionError(
            "outbound '%s': unsupported network '%s' (only xhttp/ws)" % (tag, network))
    if security not in ("reality", "tls"):
        raise ConversionError(
            "outbound '%s': unsupported security '%s' (only reality/tls)" % (tag, security))
    if network == "ws" and security == "reality":
        raise ConversionError(
            "outbound '%s': unsupported combination ws + reality" % tag)

    vnext = (outbound.get("settings") or {}).get("vnext") or []
    if not vnext:
        raise ConversionError("outbound '%s': missing settings.vnext" % tag)
    server_info = vnext[0]
    users = server_info.get("users") or []
    if not users:
        raise ConversionError("outbound '%s': missing vnext users" % tag)

    proxy = {
        "name": "%s-%s" % (network, security),
        "type": "vless",
        "server": server_info["address"],
        "port": server_info["port"],
        "uuid": users[0]["id"],
        "udp": True,
        "tls": True,
        "network": network,
        "encryption": "",
    }

    if security == "reality":
        reality = stream.get("realitySettings") or {}
        opts = {}
        if reality.get("publicKey"):
            opts["public-key"] = reality["publicKey"]
        if reality.get("shortId"):
            opts["short-id"] = reality["shortId"]
        proxy["reality-opts"] = opts
        if reality.get("serverName"):
            proxy["servername"] = reality["serverName"]
        if reality.get("fingerprint"):
            proxy["client-fingerprint"] = reality["fingerprint"]
    else:
        tls_settings = stream.get("tlsSettings") or {}
        if tls_settings.get("alpn"):
            proxy["alpn"] = tls_settings["alpn"]
        if tls_settings.get("serverName"):
            proxy["servername"] = tls_settings["serverName"]
        if tls_settings.get("fingerprint"):
            proxy["client-fingerprint"] = tls_settings["fingerprint"]

    settings = stream.get(network + "Settings") or {}
    opts = {}
    for src, dst in (("path", "path"), ("host", "host"), ("mode", "mode")):
        if settings.get(src):
            opts[dst] = settings[src]
    if opts:
        proxy[network + "-opts"] = opts

    return proxy


CONVERTERS = {
    "vless": convert_vless,
}

SKIP_PROTOCOLS = {"freedom", "blackhole"}


def convert_outbounds(outbounds):
    proxies = []
    seen = set()
    for outbound in outbounds:
        protocol = outbound.get("protocol")
        if protocol in SKIP_PROTOCOLS:
            continue
        converter = CONVERTERS.get(protocol)
        if converter is None:
            raise ConversionError(
                "outbound '%s': unsupported protocol '%s'" % (outbound.get("tag", "(untagged)"), protocol))
        proxy = converter(outbound)
        name = proxy["name"]
        base = name
        n = 2
        while name in seen:
            name = "%s%d" % (base, n)
            n += 1
        seen.add(name)
        proxy["name"] = name
        proxies.append(proxy)
    return proxies


def _dedup_names(proxies):
    seen = set()
    for proxy in proxies:
        base = proxy["name"]
        name = base
        n = 2
        while name in seen:
            name = "%s%d" % (base, n)
            n += 1
        seen.add(name)
        proxy["name"] = name
    return proxies


def parse_vless_link(link, line_no=None):
    """Parse a vless:// share link into a proxy dict."""
    def fail(msg):
        prefix = "line %d: " % line_no if line_no else ""
        raise ConversionError(prefix + msg)

    scheme, _, rest = link.partition("://")
    if not rest:
        fail("not a share link")
    if scheme != "vless":
        fail("unsupported share link scheme '%s' (only vless)" % scheme)

    fragment = None
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    userinfo, _, hostport = rest.partition("@")
    if not hostport:
        fail("missing @host:port")
    hostport, _, query_str = hostport.partition("?")
    server, _, port_str = hostport.rpartition(":")
    server = server.strip("[]")

    query = {}
    for key, value in parse_qsl(query_str, keep_blank_values=True):
        query.setdefault(key, []).append(value)

    def first(key):
        return query[key][0]

    security = first("security") if "security" in query else None
    network = first("type") if "type" in query else None
    if security not in ("reality", "tls"):
        fail("unsupported security '%s' (only reality/tls)" % security)
    if network not in ("xhttp", "ws"):
        fail("unsupported type '%s' (only xhttp/ws)" % network)
    if network == "ws" and security == "reality":
        fail("unsupported combination ws + reality")

    try:
        port = int(port_str)
    except ValueError:
        fail("invalid port '%s'" % port_str)

    proxy = {
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": userinfo,
        "udp": True,
        "tls": True,
        "network": network,
        "encryption": "",
    }

    if security == "reality":
        opts = {}
        if "pbk" in query:
            opts["public-key"] = first("pbk")
        if "sid" in query:
            opts["short-id"] = first("sid")
        proxy["reality-opts"] = opts
        if "sni" in query:
            proxy["servername"] = first("sni")
        if "fp" in query:
            proxy["client-fingerprint"] = first("fp")
    else:
        if "alpn" in query:
            proxy["alpn"] = query["alpn"]
        if "sni" in query:
            proxy["servername"] = first("sni")
        if "fp" in query:
            proxy["client-fingerprint"] = first("fp")

    opts = {}
    for key in ("path", "host", "mode"):
        if key in query:
            opts[key] = first(key)
    if opts:
        proxy[network + "-opts"] = opts

    proxy["name"] = unquote(fragment) if fragment else "%s-%s" % (network, security)
    return proxy


_LINK_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")


def parse_input(text):
    """Parse a file that may mix share-link lines and jsonc config."""
    jsonc_parts = []
    links = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if _LINK_SCHEME.match(stripped):
            links.append((line_no, stripped))
        else:
            jsonc_parts.append(raw)

    jsonc_text = "\n".join(jsonc_parts)
    data = json.loads(strip_jsonc(jsonc_text)) if jsonc_text.strip() else {}

    proxies = _dedup_names(convert_outbounds(data.get("outbounds", [])))
    for line_no, link in links:
        proxies.append(parse_vless_link(link, line_no))
    return _dedup_names(proxies)


def main(argv):
    args = argv[1:]
    output_path = None
    if "-o" in args:
        i = args.index("-o")
        if i + 1 >= len(args):
            sys.stderr.write("error: -o requires a path\n")
            return 1
        output_path = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        sys.stderr.write("usage: python xray2mihomo.py input.jsonc [-o output.yaml]\n")
        return 1

    try:
        with open(args[0], encoding="utf-8-sig") as f:
            text = f.read()
        proxies = parse_input(text)
        yaml_text = "proxies:\n" + emit_proxies(proxies)
    except (OSError, ValueError, ConversionError) as e:
        sys.stderr.write("error: %s\n" % e)
        return 1

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(yaml_text)
    else:
        sys.stdout.write(yaml_text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
