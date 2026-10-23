#!/usr/bin/env python3
"""Hermetic tests for dockerwho. Every fixture uses a temp DOCKER_CONFIG;
no docker daemon, no network, no credential helpers are ever touched."""

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dockerwho.py")


def run(args, docker_config=None, extra_env=None):
    env = dict(os.environ)
    if docker_config is not None:
        env["DOCKER_CONFIG"] = docker_config
    if extra_env:
        env.update(extra_env)
    return subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, env=env, timeout=30)


def write_config(d, cfg):
    path = os.path.join(d, "config.json")
    with open(path, "w") as fh:
        json.dump(cfg, fh)
    os.chmod(path, 0o600)  # what docker itself writes; D04b test re-opens perms
    return path


class RefParsing(unittest.TestCase):
    def test_bare_name_defaults(self):
        r = run(["ubuntu"], docker_config=tempfile.mkdtemp())
        self.assertEqual(r.returncode, 1)  # D01: no creds
        self.assertIn("registry:    docker.io", r.stdout)
        self.assertIn("repository:  library/ubuntu", r.stdout)
        self.assertIn("D05", r.stdout)

    def test_namespaced_name(self):
        r = run(["myuser/app:1.0"], docker_config=tempfile.mkdtemp())
        self.assertIn("repository:  myuser/app", r.stdout)
        self.assertIn("tag:         1.0", r.stdout)
        self.assertNotIn("namespace:library/", r.stdout)

    def test_custom_registry_with_port(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"registry.example.com:5000": {"identitytoken": "tok"}}})
        r = run(["registry.example.com:5000/ns/app"], docker_config=d)
        self.assertEqual(r.returncode, 0)
        self.assertIn("registry:    registry.example.com:5000", r.stdout)
        self.assertIn("Credential source: auths [registry.example.com:5000]", r.stdout)

    def test_localhost_is_registry(self):
        r = run(["localhost:5000/app"], docker_config=tempfile.mkdtemp())
        self.assertIn("registry:    localhost:5000", r.stdout)

    def test_digest_form(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"identitytoken": "tok"}}})
        r = run(["ubuntu@sha256:2e863c44b718727c860746568e1d54afd13b2fa71c160f5cd9058fc436217b30"],
                docker_config=d)
        self.assertEqual(r.returncode, 0)
        self.assertIn("digest:      sha256:2e863c44b718727c860746568e1d54afd13b2fa71c160f5cd9058fc436217b30",
                      r.stdout)

    def test_dotted_first_component_is_registry(self):
        r = run(["gcr.io/proj/img"], docker_config=tempfile.mkdtemp())
        self.assertIn("registry:    gcr.io", r.stdout)
        self.assertNotIn("library/", r.stdout)


class Resolution(unittest.TestCase):
    def test_hub_canonical_key(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"identitytoken": "tok"}}})
        r = run(["ubuntu"], docker_config=d)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Credential source: auths [https://index.docker.io/v1/]", r.stdout)

    def test_credhelpers_beats_credsstore(self):
        d = tempfile.mkdtemp()
        write_config(d, {"credsStore": "desktop",
                         "credHelpers": {"123456789012.dkr.ecr.us-east-1.amazonaws.com": "ecr-login"}})
        r = run(["123456789012.dkr.ecr.us-east-1.amazonaws.com/app"], docker_config=d)
        self.assertIn("Credential source: credHelpers [123456789012.dkr.ecr.us-east-1.amazonaws.com]",
                      r.stdout)
        self.assertIn("ecr-login", r.stdout)

    def test_credsstore_fallback(self):
        d = tempfile.mkdtemp()
        write_config(d, {"credsStore": "desktop"})
        r = run(["quay.io/org/app"], docker_config=d)
        self.assertEqual(r.returncode, 0)
        self.assertIn("Credential source: credsStore", r.stdout)
        self.assertIn("desktop", r.stdout)

    def test_missing_config_is_d01(self):
        d = tempfile.mkdtemp()  # no config.json written
        r = run(["ubuntu"], docker_config=d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("D01", r.stdout)
        self.assertIn("no docker config file found", r.stdout)

    def test_malformed_config_is_exit2(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "config.json"), "w") as fh:
            fh.write("{not json")
        r = run(["ubuntu"], docker_config=d)
        self.assertEqual(r.returncode, 2)

    def test_explicit_config_flag(self):
        d = tempfile.mkdtemp()
        p = write_config(d, {"auths": {"https://index.docker.io/v1/": {"identitytoken": "tok"}}})
        r = run(["--config", p, "ubuntu"], docker_config="/nonexistent")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Credential source: auths", r.stdout)


class Rules(unittest.TestCase):
    def test_d02_variant_key(self):
        d = tempfile.mkdtemp()
        # docker looks up https://index.docker.io/v1/; this variant may be missed
        write_config(d, {"auths": {"docker.io": {"auth": "eA=="}}})
        r = run(["ubuntu"], docker_config=d)
        self.assertIn("D02", r.stdout)
        self.assertIn("non-canonical", r.stdout)

    def test_d03_ecr_login_for_hub(self):
        d = tempfile.mkdtemp()
        write_config(d, {"credsStore": "ecr-login"})
        r = run(["ubuntu"], docker_config=d)
        self.assertIn("D03", r.stdout)

    def test_d03_not_fired_for_ecr_target(self):
        d = tempfile.mkdtemp()
        write_config(d, {"credHelpers": {"123456789012.dkr.ecr.us-east-1.amazonaws.com": "ecr-login"}})
        r = run(["123456789012.dkr.ecr.us-east-1.amazonaws.com/app"], docker_config=d)
        self.assertNotIn("D03", r.stdout)

    def test_d04_base64_blob_warns(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"}}})
        r = run(["ubuntu"], docker_config=d)
        self.assertIn("D04", r.stdout)
        self.assertIn("not encryption", r.stdout)

    def test_d04b_world_readable(self):
        d = tempfile.mkdtemp()
        p = write_config(d, {"auths": {"https://index.docker.io/v1/": {"identitytoken": "tok"}}})
        os.chmod(p, 0o644)
        r = run(["ubuntu"], docker_config=d)
        self.assertIn("D04b", r.stdout)

    def test_d06_empty_auths_info(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {}},
                         "credsStore": "desktop"})
        # credsStore wins, so empty-auths D06 should not appear
        r = run(["ubuntu"], docker_config=d)
        self.assertNotIn("D06", r.stdout)
        d2 = tempfile.mkdtemp()
        write_config(d2, {"auths": {"https://index.docker.io/v1/": {}}})
        r2 = run(["ubuntu"], docker_config=d2)
        self.assertIn("D06", r2.stdout)

    def test_info_only_does_not_flip_exit(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"identitytoken": "tok"}}})
        r = run(["ubuntu"], docker_config=d)
        self.assertEqual(r.returncode, 0)  # only D05(info) fires


class Safety(unittest.TestCase):
    def test_never_decodes_credentials(self):
        d = tempfile.mkdtemp()
        # base64("supersecretuser:supersecretpass")
        blob = "c3VwZXJzZWNyZXR1c2VyOnN1cGVyc2VjcmV0cGFzcw=="
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"auth": blob}}})
        r = run(["ubuntu", "--json"], docker_config=d)
        self.assertNotIn("supersecretuser", r.stdout)
        self.assertNotIn("supersecretpass", r.stdout)
        self.assertNotIn(blob, r.stdout)

    def test_never_invokes_helpers(self):
        d = tempfile.mkdtemp()
        marker = os.path.join(d, "helper-was-invoked")
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "docker-credential-evil"), "w") as fh:
            fh.write("#!/bin/sh\ntouch %s\n" % marker)
        os.chmod(os.path.join(bindir, "docker-credential-evil"), 0o755)
        write_config(d, {"credHelpers": {"quay.io": "evil"}})
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
        r = subprocess.run([sys.executable, TOOL, "quay.io/org/app"],
                           capture_output=True, text=True, env={**env, "DOCKER_CONFIG": d},
                           timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(marker), "credential helper must never be executed")
        self.assertIn("never invoked", r.stdout)


class Output(unittest.TestCase):
    def test_json_shape(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"identitytoken": "tok"}}})
        r = run(["ubuntu", "--json"], docker_config=d)
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(data["registry"], "docker.io")
        self.assertEqual(data["repository"], "library/ubuntu")
        self.assertEqual(data["credential"]["source"], "auths")
        self.assertIsInstance(data["findings"], list)

    def test_list_mode(self):
        d = tempfile.mkdtemp()
        write_config(d, {"auths": {"https://index.docker.io/v1/": {"auth": "eA=="}},
                         "credHelpers": {"ghcr.io": "1password"},
                         "credsStore": "desktop"})
        r = run(["--list"], docker_config=d)
        self.assertEqual(r.returncode, 0)
        self.assertIn("https://index.docker.io/v1/", r.stdout)
        self.assertIn("ghcr.io", r.stdout)
        self.assertIn("1password", r.stdout)

    def test_version(self):
        r = run(["--version"])
        self.assertEqual(r.returncode, 0)
        self.assertIn("dockerwho", r.stdout)

    def test_no_args_is_exit2(self):
        r = run([], docker_config=tempfile.mkdtemp())
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
