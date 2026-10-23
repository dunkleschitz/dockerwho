#!/usr/bin/env python3
"""dockerwho - which registry and credentials will `docker push` actually use?

Resolves an image reference to its fully-qualified form (registry,
repository, tag/digest) and reports which credential source docker will
consult for that registry -- auths / credHelpers / credsStore -- with
file-of-origin evidence and hygiene rules over the result.

Model honesty: this is a static model of docker's documented credential
resolution (verified against docker config examples 2026-10-23). docker
itself is the final authority; a real `docker push` is the real test.
This tool NEVER decodes stored credentials, NEVER invokes credential
helpers, and NEVER contacts any registry.

Exit codes: 0 clean · 1 findings · 2 usage/config error.
"""

import argparse
import json
import os
import stat
import sys

VERSION = "1.0.0"

# Canonical credential key docker uses for Docker Hub. Verified 2026-10-23:
# every real-world `docker login` example stores hub creds under this key.
HUB_LOOKUP_KEY = "https://index.docker.io/v1/"
HUB_HOSTS = {"docker.io", "index.docker.io"}

# DOCKER_CONFIG env var redirects the config dir; default ~/.docker.
# [docker-documented]
DEFAULT_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".docker")

# Known cloud-only credential helpers: they mint tokens for their cloud's
# registry and cannot serve docker.io. [dockerwho-heuristic]
CLOUD_ONLY_HELPERS = ("ecr-login", "gcr", "gcloud", "acr")


# --------------------------------------------------------------------------
# Image reference parsing
# --------------------------------------------------------------------------

def parse_reference(ref):
    """Split an image reference into (registry_host, repository, tag, digest,
    defaults_applied). Registry detection rule: the first path component is
    a registry iff it contains '.' or ':' or is 'localhost'. [docker-documented]
    """
    defaults = []
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = "latest"
    if ":" in ref.rsplit("/", 1)[-1]:
        ref, tag = ref.rsplit(":", 1)
    else:
        defaults.append("tag:latest")
    parts = ref.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts[0]
        repository = "/".join(parts[1:])
    else:
        registry = "docker.io"
        repository = ref
        defaults.append("registry:docker.io")
    if registry == "docker.io" and "/" not in repository:
        repository = "library/" + repository
        defaults.append("namespace:library/")
    if not repository:
        raise ValueError("empty repository in image reference %r" % ref)
    return registry, repository, tag, digest, defaults


def lookup_key(registry_host):
    """The primary credential key docker consults for this registry."""
    if registry_host in HUB_HOSTS:
        return HUB_LOOKUP_KEY
    return registry_host


def candidate_keys(registry_host):
    """Keys to try, most-canonical first. The non-primary candidates are
    forms docker login sometimes stores but docker may not consult at push
    time -- matches there surface as D02. [docker-documented]+[heuristic]
    """
    primary = lookup_key(registry_host)
    cands = [primary]
    for alt in (registry_host,
                "https://" + registry_host + "/v1/",
                "http://" + registry_host + "/v1/"):
        if alt != primary and alt not in cands:
            cands.append(alt)
    return cands


# --------------------------------------------------------------------------
# Config loading
# --------------------------------------------------------------------------

def config_dir():
    return os.environ.get("DOCKER_CONFIG") or DEFAULT_CONFIG_DIR


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise ConfigError("%s: top-level JSON must be an object" % path)
    return data


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------
# Credential resolution
# --------------------------------------------------------------------------

def resolve_credential(registry_host, cfg):
    """Return (source, key, note). source in auths|credHelpers|credsStore|none.
    NEVER decodes or invokes anything: values are only inspected for presence.
    """
    if cfg is None:
        return ("none", None, "no docker config file found")
    helpers = cfg.get("credHelpers") or {}
    auths = cfg.get("auths") or {}
    if not isinstance(helpers, dict):
        helpers = {}
    if not isinstance(auths, dict):
        auths = {}

    for key in candidate_keys(registry_host):
        if key in helpers and helpers[key]:
            canon = "canonical" if key == candidate_keys(registry_host)[0] else "non-canonical"
            return ("credHelpers", key,
                    "helper %r configured for key %r (%s form; helper is never invoked, "
                    "so dockerwho cannot verify it actually holds credentials)"
                    % (helpers[key], key, canon))
    store = cfg.get("credsStore")
    if store:
        return ("credsStore", None,
                "global helper %r serves every registry (never invoked by dockerwho)" % store)

    for key in candidate_keys(registry_host):
        if key in auths:
            entry = auths[key]
            canon = "canonical" if key == candidate_keys(registry_host)[0] else "non-canonical"
            if isinstance(entry, dict) and not entry:
                return ("auths", key,
                        "entry %r is empty -- credentials live in a helper/credStore, "
                        "this only reserves the key (%s form)" % (key, canon))
            has_auth = isinstance(entry, dict) and bool(entry.get("auth"))
            has_token = isinstance(entry, dict) and bool(entry.get("identitytoken"))
            what = "base64 auth blob" if has_auth else ("identity token" if has_token else "entry")
            return ("auths", key,
                    "credentials configured (%s, %s form); value never decoded" % (what, canon))
    return ("none", None, "no auths entry, no credHelpers entry, no credsStore")


# --------------------------------------------------------------------------
# Hygiene rules
# --------------------------------------------------------------------------

def check_rules(registry_host, repository, tag, digest, defaults, cfg, cfg_path,
                source, key):
    findings = []

    def add(rid, severity, text):
        findings.append({"id": rid, "severity": severity, "text": text})

    if source == "none":
        add("D01", "error",
            "no credential source configured for registry %r -- `docker push` "
            "to it will fail with an auth error (push always requires login)" % registry_host)

    # D02: auths entry exists under a non-canonical key form only.
    auths = (cfg.get("auths") or {}) if isinstance(cfg, dict) else {}
    canon = lookup_key(registry_host)
    if source == "none" or (source == "auths" and key != canon):
        variants = [k for k in auths
                    if k != canon and _same_registry_form(k, registry_host)]
        if variants:
            add("D02", "warning",
                "auths has entries under non-canonical key form(s) %s; docker's "
                "lookup consults %r, so these may be silently ignored -- consolidate "
                "under the canonical key" % (", ".join(sorted(variants)), canon))

    # D03: global credsStore helper that cannot serve docker.io.
    if isinstance(cfg, dict):
        store = cfg.get("credsStore")
        if store and registry_host in HUB_HOSTS and any(
                h in store for h in CLOUD_ONLY_HELPERS):
            add("D03", "warning",
                "credsStore is %r, a cloud-only helper that cannot serve docker.io -- "
                "pushes to Docker Hub will fail; use per-registry credHelpers instead" % store)

    # D04: legacy unencrypted base64 auth in config.json.
    if isinstance(cfg, dict):
        for k, v in auths.items():
            if isinstance(v, dict) and v.get("auth"):
                add("D04", "warning",
                    "config.json stores a base64 auth blob for %r -- base64 is an "
                    "encoding, not encryption; prefer a credential helper" % k)
                break
    if cfg_path and os.path.exists(cfg_path):
        mode = os.stat(cfg_path).st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH) and auths:
            add("D04b", "warning",
                "%s is readable by group/other while holding registry credentials" % cfg_path)

    # D05: implicit defaults (the "pushed to docker.io, not my registry" footgun).
    if defaults:
        add("D05", "info",
            "reference used implicit defaults (%s) -- fully-qualified form is "
            "%s/%s%s; if you meant a private registry, qualify it explicitly"
            % (", ".join(defaults), registry_host, repository,
               (":" + tag) if not digest else "@" + digest))

    # D06: empty auths entry reserves a key for helper-managed creds.
    if source == "auths" and key and isinstance(auths.get(key), dict) and not auths.get(key):
        add("D06", "info",
            "auths[%r] is empty -- credentials are helper-managed; this entry only "
            "reserves the key (seen with 1password-style credHelpers setups)" % key)

    return findings


def _same_registry_form(key, registry_host):
    """Does an auths key look like a scheme/path variant of this registry?"""
    k = key.lower().rstrip("/")
    h = registry_host.lower()
    if k in (h, "https://" + h, "http://" + h):
        return True
    for suffix in ("/v1/", "/v2/", "/v1", "/v2"):
        if k == "https://" + h + suffix or k == "http://" + h + suffix:
            return True
    return False


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

def build_report(image, cfg, cfg_path):
    registry, repository, tag, digest, defaults = parse_reference(image)
    source, key, note = resolve_credential(registry, cfg)
    findings = check_rules(registry, repository, tag, digest, defaults,
                           cfg, cfg_path, source, key)
    return {
        "image": image,
        "registry": registry,
        "repository": repository,
        "tag": tag,
        "digest": digest,
        "defaults_applied": defaults,
        "config_file": cfg_path,
        "credential": {"source": source, "key": key, "note": note},
        "findings": findings,
    }


def render_text(image, report):
    lines = []
    lines.append("dockerwho: effective push target for %r" % image)
    lines.append("")
    lines.append("Target:")
    lines.append("  registry:    %s" % report["registry"])
    lines.append("  repository:  %s" % report["repository"])
    lines.append("  tag:         %s" % (report["tag"] if not report["digest"] else "(digest-pinned)"))
    if report["digest"]:
        lines.append("  digest:      %s" % report["digest"])
    if report["defaults_applied"]:
        lines.append("  defaults:    %s (see D05)" % ", ".join(report["defaults_applied"]))
    lines.append("")
    lines.append("Config: %s" % (report["config_file"] or "(none found)"))
    cred = report["credential"]
    lines.append("Credential source: %s%s" % (
        cred["source"], (" [%s]" % cred["key"]) if cred["key"] else ""))
    lines.append("  %s" % cred["note"])
    lines.append("")
    findings = report["findings"]
    if findings:
        lines.append("Findings (%d):" % len(findings))
        for f in findings:
            lines.append("  %s [%s] %s" % (f["id"], f["severity"], f["text"]))
    else:
        lines.append("Findings: none -- credentials are configured for %s" % report["registry"])
    return "\n".join(lines)


def list_registries(cfg, cfg_path):
    """Every registry with any credential configuration, and its source."""
    rows = []
    if isinstance(cfg, dict):
        helpers = cfg.get("credHelpers") or {}
        auths = cfg.get("auths") or {}
        keys = []
        for k in list(helpers.keys()) + list(auths.keys()):
            if k not in keys:
                keys.append(k)
        for k in sorted(keys):
            if k in helpers and helpers[k]:
                src = "credHelpers (%s)" % helpers[k]
            elif isinstance(auths.get(k), dict) and auths.get(k):
                src = "auths (stored blob, never decoded)"
            else:
                src = "auths (empty -- helper-managed)"
            rows.append((k, src))
        if cfg.get("credsStore"):
            rows.append(("(all other registries)", "credsStore (%s)" % cfg["credsStore"]))
    return rows


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="dockerwho",
        description="Resolve which registry a `docker push` targets and which "
                    "credential source docker will consult -- without pushing, "
                    "decoding credentials, or invoking helpers.")
    ap.add_argument("image", nargs="?", help="image reference, e.g. myapp:1.0 or registry:5000/ns/app")
    ap.add_argument("--list", action="store_true",
                    help="list every registry with configured credentials instead of resolving one image")
    ap.add_argument("--config", metavar="PATH",
                    help="use this docker config.json instead of $DOCKER_CONFIG/~/.docker/config.json")
    ap.add_argument("--json", action="store_true", help="machine-readable report")
    ap.add_argument("--version", action="store_true", help="print version and exit")
    args = ap.parse_args(argv)

    if args.version:
        print("dockerwho %s" % VERSION)
        return 0
    if args.list and args.image:
        ap.error("--list takes no image argument")
    if not args.list and not args.image:
        ap.error("an image reference is required (or --list)")

    cfg_path = args.config or os.path.join(config_dir(), "config.json")
    try:
        cfg = load_config(cfg_path)
    except ConfigError as exc:
        print("dockerwho: %s" % exc, file=sys.stderr)
        return 2

    if args.list:
        rows = list_registries(cfg, cfg_path)
        if args.json:
            print(json.dumps({"config_file": cfg_path,
                              "registries": [{"key": k, "source": s} for k, s in rows]},
                             indent=2, sort_keys=True))
        else:
            print("dockerwho: registries with configured credentials")
            print("config: %s" % cfg_path)
            if rows:
                for k, s in rows:
                    print("  %-40s %s" % (k, s))
            else:
                print("  (none)")
        return 0

    try:
        report = build_report(args.image, cfg, cfg_path)
    except ValueError as exc:
        print("dockerwho: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(args.image, report))
        print("")
        print("model: static interpretation of docker's documented credential resolution "
              "(verified 2026-10-23); docker itself is the final authority")

    errors = [f for f in report["findings"] if f["severity"] in ("error", "warning")]
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
