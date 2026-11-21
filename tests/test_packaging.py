"""Checks that the repository hangs together: the data files are well formed, the
containers include what the programs need, the dashboard and the server agree on the
API, and the "standard library only" promise is kept.

Run with:  python3 -m unittest discover tests

These read files only. Nothing is built, started or sent anywhere.
"""
import ast
import collections
import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import server  # noqa: E402

LOCAL_MODULES = {"server", "enforcer", "cloud_agent", "relay"}


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


def imports_of(path):
    """Top-level module names a Python file imports."""
    names = set()
    for node in ast.walk(ast.parse(read(path))):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module.split(".")[0])
    return names


def copied_into(dockerfile):
    """Every source path named on a COPY line of a Dockerfile."""
    out = set()
    for line in read(dockerfile).splitlines():
        if line.startswith("COPY "):
            out.update(line.split()[1:-1])
    return out


class StandardLibraryOnly(unittest.TestCase):
    PROGRAMS = ["server.py", "enforcer.py", "cloud_agent.py", os.path.join("cloud", "relay.py")]

    @unittest.skipUnless(hasattr(sys, "stdlib_module_names"), "needs Python 3.10 or newer to list the standard library")
    def test_nothing_outside_python_itself_is_imported(self):
        for path in self.PROGRAMS:
            extra = imports_of(path) - set(sys.stdlib_module_names) - LOCAL_MODULES
            self.assertEqual(extra, set(), "%s imports something that would need installing" % path)

    @unittest.skipUnless(hasattr(sys, "stdlib_module_names"), "needs Python 3.10 or newer to list the standard library")
    def test_the_tests_need_nothing_installed_either(self):
        tests = os.path.join(ROOT, "tests")
        local = LOCAL_MODULES | {f[:-3] for f in os.listdir(tests) if f.endswith(".py")}
        for name in sorted(os.listdir(tests)):
            if name.endswith(".py"):
                extra = imports_of(os.path.join("tests", name)) - set(sys.stdlib_module_names) - local
                self.assertEqual(extra, set(), name)

    def test_the_relay_does_not_depend_on_the_pi_programs(self):
        # The relay's container holds relay.py alone, so it must not import the others.
        self.assertEqual(imports_of(os.path.join("cloud", "relay.py")) & LOCAL_MODULES, set())


class Containers(unittest.TestCase):
    @unittest.expectedFailure
    def test_the_pi_container_includes_every_program_file_the_server_imports(self):
        # KNOWN ISSUE 1 (docs/KNOWN_ISSUES.md): server.py imports cloud_agent, but the Dockerfile
        # does not copy cloud_agent.py, so the container stops at start-up. When the Dockerfile is
        # fixed this check will start passing; remove the expectedFailure line above at that point.
        needed = {m + ".py" for m in imports_of("server.py") & LOCAL_MODULES}
        self.assertEqual(needed - copied_into("Dockerfile"), set())

    def test_the_pi_container_includes_the_data_files_and_dashboard(self):
        self.assertLessEqual({"server.py", "enforcer.py", "services.json", "junk_domains.txt", "static"},
                             copied_into("Dockerfile"))

    def test_the_pi_container_has_the_firewall_tool_the_enforcer_uses(self):
        self.assertIn("nftables", read("Dockerfile"))

    def test_the_relay_container_includes_the_relay_and_the_dashboard(self):
        self.assertLessEqual({"cloud/relay.py", "static"}, copied_into(os.path.join("cloud", "Dockerfile")))

    def test_the_relay_container_declares_no_volume(self):
        # Railway refuses to build an image with a VOLUME line (see CHANGELOG 0.5).
        lines = [l for l in read("cloud", "Dockerfile").splitlines() if l.strip().upper().startswith("VOLUME")]
        self.assertEqual(lines, [])

    def test_railway_is_pointed_at_the_relay_container(self):
        cfg = json.loads(read("railway.json"))
        self.assertEqual(cfg["build"]["dockerfilePath"], "cloud/Dockerfile")
        self.assertTrue(os.path.exists(os.path.join(ROOT, cfg["build"]["dockerfilePath"])))

    def test_compose_gives_the_pi_what_the_enforcer_and_dns_need(self):
        compose = read("docker-compose.yml")
        for needed in ("network_mode: host", "NET_ADMIN", "NET_RAW", "/data", "restart: unless-stopped"):
            self.assertIn(needed, compose)

    def test_every_copied_path_exists(self):
        for dockerfile in ("Dockerfile", os.path.join("cloud", "Dockerfile")):
            for path in copied_into(dockerfile):
                self.assertTrue(os.path.exists(os.path.join(ROOT, path)), "%s copies missing %s" % (dockerfile, path))


class ServiceCatalogue(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.services = json.loads(read("services.json"))

    def test_every_service_has_an_id_a_name_a_category_and_addresses(self):
        for v in self.services:
            self.assertEqual(set(v), {"id", "name", "cat", "domains"}, v)
            self.assertRegex(v["id"], r"^[a-z0-9]+$")
            self.assertTrue(v["name"].strip() and v["cat"].strip() and v["domains"], v["id"])

    def test_ids_are_unique(self):
        ids = [v["id"] for v in self.services]
        self.assertEqual(len(ids), len(set(ids)))

    def test_addresses_are_well_formed_and_lower_case(self):
        for v in self.services:
            for d in v["domains"]:
                self.assertTrue(server.VALID_NAME.fullmatch(d), "%s: %r" % (v["id"], d))
                self.assertFalse(d.startswith("www."), d)

    def test_no_address_belongs_to_two_services(self):
        # Each address maps to one service; a second claim would silently replace the first.
        counts = collections.Counter(d for v in self.services for d in v["domains"])
        self.assertEqual([d for d, n in counts.items() if n > 1], [])

    def test_no_service_sits_under_another_services_address(self):
        # e.g. if "google.com" were one service, "youtube.google.com" under another would never be reached.
        owner = {d: v["id"] for v in self.services for d in v["domains"]}
        for d, sid in owner.items():
            for parent in server.suffixes(d)[1:]:
                self.assertIn(owner.get(parent, sid), (sid,), "%s sits under %s" % (d, parent))

    def test_no_service_address_is_on_the_built_in_advert_list(self):
        # Otherwise the service would be blocked for everyone before anyone chose to block it.
        junk = {l.strip().lower() for l in read("junk_domains.txt").splitlines() if l.strip() and not l.startswith("#")}
        for v in self.services:
            for d in v["domains"]:
                self.assertFalse(any(s in junk for s in server.suffixes(d)), d)


class AdvertList(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entries = [l.strip() for l in read("junk_domains.txt").splitlines() if l.strip() and not l.startswith("#")]

    def test_entries_are_well_formed_lower_case_addresses(self):
        for d in self.entries:
            self.assertTrue(server.VALID_NAME.fullmatch(d), repr(d))

    def test_there_are_no_duplicates(self):
        counts = collections.Counter(self.entries)
        self.assertEqual([d for d, n in counts.items() if n > 1], [])

    def test_everyday_sites_are_not_on_it(self):
        junk = set(self.entries)
        for site in ("google.com", "apple.com", "bbc.co.uk", "amazon.co.uk", "microsoft.com", "netflix.com",
                     "youtube.com", "icloud.com", "whatsapp.net", "github.com"):
            self.assertFalse(any(s in junk for s in server.suffixes("www." + site)), site)

    def test_owner_names_are_keyed_by_addresses_the_grouping_can_produce(self):
        for d in server.OWNERS:
            self.assertEqual(server.base_of(d), d, "%r can never match: activity is grouped as %r" % (d, server.base_of(d)))


class DashboardContract(unittest.TestCase):
    """The dashboard page is served twice: by the Pi directly, and by the relay, which
    edits it on the way through. These checks protect the things each side relies on."""

    @classmethod
    def setUpClass(cls):
        cls.page = read("static", "index.html")

    def test_every_api_address_the_dashboard_calls_exists_on_the_server(self):
        called = set(re.findall(r"""['"`](/api/[a-z-]+)""", self.page))
        self.assertGreater(len(called), 15)
        handled = set(re.findall(r"""["'](/api/[a-z-]+)["']""", read("server.py")))
        self.assertEqual(called - handled, set())

    def test_the_dashboard_marks_its_requests_for_the_relay(self):
        # The relay refuses API calls without this header (its guard against forged requests).
        self.assertIn("'X-QuietNet': '1'", self.page)

    def test_the_dashboard_can_be_pointed_at_a_relayed_pi(self):
        self.assertIn("window.QN_API_BASE", self.page)

    def test_the_page_has_the_two_tags_the_relay_inserts_after(self):
        # relay.serve_dashboard does a plain text replace on these exact tags.
        self.assertEqual(self.page.count("<head>"), 1)
        self.assertEqual(self.page.count("<body>"), 1)

    def test_the_page_loads_nothing_from_other_websites(self):
        self.assertEqual(re.findall(r"""(?:src|href)=["']https?://""", self.page), [])


class Readme(unittest.TestCase):
    def test_every_top_level_file_is_listed_in_the_readme(self):
        readme = read("README.md")
        for name in ("server.py", "enforcer.py", "cloud_agent.py", "services.json", "junk_domains.txt",
                     "Start QuietNet.command", "Dockerfile", "docker-compose.yml", "static/index.html"):
            self.assertIn("`%s`" % name, readme, name)

    def test_the_documents_the_readme_links_to_exist(self):
        for doc in re.findall(r"\]\(((?:docs|cloud)/[^)#]+)", read("README.md")):
            self.assertTrue(os.path.exists(os.path.join(ROOT, doc)), doc)

    def test_the_changelog_has_an_entry_for_every_version(self):
        versions = re.findall(r"^## (\d+\.\d+)", read("CHANGELOG.md"), flags=re.M)
        self.assertEqual(versions, sorted(versions, key=lambda v: [int(x) for x in v.split(".")], reverse=True))
        self.assertGreaterEqual(len(versions), 5)


if __name__ == "__main__":
    unittest.main()
