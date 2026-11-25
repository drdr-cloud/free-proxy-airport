"""Convert output/clash.yaml to V2Ray subscription (base64 links).
Reads output/clash.yaml, writes output/v2ray.txt (base64) and
output/v2ray-links.txt (plain, one link per line).
Skips proxy types V2Ray core does not support (e.g. hysteria2).
"""
from __future__ import annotations
import base64, json, urllib.parse
from pathlib import Path
import yaml

INPUT = Path("output/clash.yaml")
OUT_B64 = Path("output/v2ray.txt")
OUT_PLAIN = Path("output/v2ray-links.txt")

def b64u(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")

def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def convert(p: dict) -> str | None:
    name = p["name"]; t = p.get("type"); srv = p.get("server"); port = p.get("port")
    if t == "vmess":
        vm = {"v": "2", "ps": name, "add": srv, "port": str(port),
              "id": p.get("uuid"), "aid": str(p.get("alterId", 0)),
              "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
              "type": "none", "host": "", "path": "",
              "tls": "tls" if p.get("tls") else "",
              "sni": p.get("servername", ""), "alpn": "", "fp": ""}
        if p.get("network") == "ws":
            o = p.get("ws-opts", {}) or {}
            vm["path"] = o.get("path", "")
            h = o.get("headers", {}) or {}
            vm["host"] = h.get("Host", "")
        elif p.get("network") == "http":
            o = p.get("http-opts", {}) or {}
            paths = o.get("path", []) or []
            vm["path"] = paths[0] if paths else ""
            h = o.get("headers", {}) or {}
            hosts = h.get("Host", []) or []
            vm["host"] = hosts[0] if isinstance(hosts, list) and hosts else (hosts if isinstance(hosts, str) else "")
        return "vmess://" + b64(json.dumps(vm, ensure_ascii=False))
    if t == "vless":
        q: dict[str, str] = {"encryption": "none"}
        q["security"] = "reality" if p.get("reality-opts") else ("tls" if p.get("tls") else "none")
        if p.get("flow"):
            q["flow"] = p["flow"]
        net = p.get("network", "tcp")
        q["type"] = net
        if p.get("servername"):
            q["sni"] = p["servername"]
        if p.get("client-fingerprint"):
            q["fp"] = p["client-fingerprint"]
        if p.get("alpn"):
            q["alpn"] = ",".join(p["alpn"])
        ro = p.get("reality-opts") or {}
        if ro.get("public-key"):
            q["pbk"] = ro["public-key"]
        if ro.get("short-id"):
            q["sid"] = ro["short-id"]
        if net == "ws":
            o = p.get("ws-opts", {}) or {}
            if o.get("path"):
                q["path"] = o["path"]
            h = o.get("headers", {}) or {}
            if h.get("Host"):
                q["host"] = h["Host"]
        elif net == "grpc":
            o = p.get("grpc-opts", {}) or {}
            if o.get("grpc-service-name"):
                q["serviceName"] = o["grpc-service-name"]
            if o.get("grpc-mode"):
                q["mode"] = o["grpc-mode"]
        elif net == "xhttp":
            o = p.get("xhttp-opts", {}) or {}
            if o.get("path"):
                q["path"] = o["path"]
            if o.get("host"):
                q["host"] = o["host"]
            if o.get("mode"):
                q["mode"] = o["mode"]
        return f"vless://{p.get('uuid')}@{srv}:{port}?{urllib.parse.urlencode(q)}#{urllib.parse.quote(name)}"
    if t == "ss":
        cred = f"{p.get('cipher')}:{p.get('password')}@{srv}:{port}"
        return f"ss://{b64u(cred)}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q: dict[str, str] = {}
        if p.get("sni"):
            q["sni"] = p["sni"]
        if p.get("skip-cert-verify"):
            q["allowInsecure"] = "1"
        qs = f"?{urllib.parse.urlencode(q)}" if q else ""
        return f"trojan://{urllib.parse.quote(str(p.get('password')))}@{srv}:{port}{qs}#{urllib.parse.quote(name)}"
    return None

def main() -> None:
    data = yaml.safe_load(INPUT.read_text(encoding="utf-8"))
    links: list[str] = []
    skipped: list[str] = []
    for p in data.get("proxies", []):
        try:
            link = convert(p)
        except Exception as exc:
            link = None
            print(f"[SKIP] {p.get('name')} error: {exc}")
        if link:
            links.append(link)
        else:
            skipped.append(f"{p.get('name')} ({p.get('type')})")
    if not links:
        raise SystemExit("no V2Ray links converted")
    OUT_B64.parent.mkdir(parents=True, exist_ok=True)
    OUT_B64.write_text(b64("\n".join(links)), encoding="utf-8")
    OUT_PLAIN.write_text("\n".join(links) + "\n", encoding="utf-8")
    print(f"[SUMMARY] proxies={len(data.get('proxies', []))} converted={len(links)} skipped={len(skipped)}")
    for s in skipped:
        print(f"[SKIP] {s}")
    print(f"[SUMMARY] output={OUT_B64} {OUT_PLAIN}")

if __name__ == "__main__":
    main()
