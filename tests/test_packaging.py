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

LOCAL_MODULES = {"server", "names", "enforcer", "cloud_agent", "relay"}


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
    PROGRAMS = ["server.py", "names.py", "enforcer.py", "cloud_agent.py", os.path.join("cloud", "relay.py")]

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


class Commenting(unittest.TestCase):
    """The programs are meant to be readable by whoever (or whatever) picks them up next."""
    PROGRAMS = StandardLibraryOnly.PROGRAMS

    def test_every_function_and_class_explains_itself(self):
        for path in self.PROGRAMS:
            tree = ast.parse(read(path))
            self.assertTrue(ast.get_docstring(tree), "%s needs an opening description" % path)
            silent = [node.name for node in ast.walk(tree)
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not ast.get_docstring(node)]
            self.assertEqual(silent, [], "%s: add a docstring saying what these do and why" % path)

    def test_the_dashboard_script_opens_with_its_notes_for_editors(self):
        page = read("static", "index.html")
        notes = page[page.index("<script>"):page.index("const S = {")]
        for must in ("HOW IT IS ORGANISED", "esc()", "data-act", "QN_API_BASE"):
            self.assertIn(must, notes)

    def test_the_guide_for_agents_exists_and_names_the_test_command(self):
        guide = read("AGENTS.md")
        self.assertIn("python3 -m unittest discover tests", guide)
        self.assertIn("AGENTS.md", read("CLAUDE.md"))


class Containers(unittest.TestCase):
    def test_the_pi_container_includes_every_program_file_the_server_imports(self):
        # A file the server imports but the Dockerfile leaves out stops the container at start-up
        # (this happened to cloud_agent.py in 0.5).
        needed = {m + ".py" for m in imports_of("server.py") & LOCAL_MODULES}
        self.assertEqual(needed - copied_into("Dockerfile"), set())

    def test_the_pi_container_includes_the_data_files_and_dashboard(self):
        self.assertLessEqual({"server.py", "names.py", "enforcer.py", "services.json", "junk_domains.txt", "static"},
                             copied_into("Dockerfile"))

    def test_the_pi_container_has_the_firewall_tool_the_enforcer_uses(self):
        self.assertIn("nftables", read("Dockerfile"))

    def test_the_relay_container_includes_the_relay_and_the_dashboard(self):
        self.assertLessEqual({"cloud/relay.py", "static"}, copied_into(os.path.join("cloud", "Dockerfile")))

    def test_the_relay_container_writes_its_log_out_unbuffered(self):
        # The host reads the relay's output through a pipe; without this a start-up line such as
        # "Licence gate: on" could sit in Python's buffer, or be lost when the relay is stopped.
        lines = [l.split() for l in read("cloud", "Dockerfile").splitlines() if l.strip().upper().startswith("ENV")]
        self.assertIn(["ENV", "PYTHONUNBUFFERED=1"], lines)

    def test_the_relay_container_declares_no_volume(self):
        # Railway refuses to build an image with a VOLUME line (see CHANGELOG 0.5).
        lines = [l for l in read("cloud", "Dockerfile").splitlines() if l.strip().upper().startswith("VOLUME")]
        self.assertEqual(lines, [])

    def test_the_relay_container_starts_as_root_so_it_can_take_over_the_volume(self):
        # Railway's volume belongs to root; relay.py hands it to an ordinary user and drops root itself.
        lines = [l for l in read("cloud", "Dockerfile").splitlines() if l.strip().upper().startswith("USER")]
        self.assertEqual(lines, [])

    def test_railway_is_pointed_at_the_relay_container(self):
        cfg = json.loads(read("railway.json"))
        self.assertEqual(cfg["build"]["dockerfilePath"], "cloud/Dockerfile")
        self.assertTrue(os.path.exists(os.path.join(ROOT, cfg["build"]["dockerfilePath"])))

    def test_compose_gives_the_pi_what_the_enforcer_and_dns_need(self):
        compose = read("docker-compose.yml")
        for needed in ("network_mode: host", "NET_ADMIN", "NET_RAW", "/data", "restart: unless-stopped"):
            self.assertIn(needed, compose)

    def test_compose_lets_a_pi_with_no_screen_be_paired(self):
        # The dashboard only opens on the Pi itself, so these two settings are the way in.
        compose = read("docker-compose.yml")
        self.assertIn("QUIETNET_CLOUD=${QUIETNET_CLOUD:-}", compose)
        self.assertIn("QUIETNET_PAIR=${QUIETNET_PAIR:-}", compose)

    def test_compose_allows_time_for_the_enforcer_to_restore_the_network(self):
        grace = int(re.search(r"stop_grace_period: (\d+)s", read("docker-compose.yml")).group(1))
        self.assertGreater(grace, 15)          # longer than Enforcer.stop() is prepared to wait

    def test_the_pi_container_installs_the_time_zone_tables(self):
        # Without them the container can only run on UTC, and schedules fire at the wrong hour.
        install = [l for l in read("Dockerfile").splitlines() if "apt-get install" in l]
        self.assertTrue(any("tzdata" in l for l in install))

    def test_the_pi_container_installs_the_tool_that_reads_ipv6_neighbours(self):
        # Without `ip`, devices asking over IPv6 can't be matched to their rules and are refused.
        install = [l for l in read("Dockerfile").splitlines() if "apt-get install" in l]
        self.assertTrue(any("iproute2" in l for l in install))

    def test_compose_shares_the_pis_time_zone_with_the_container(self):
        self.assertIn("- /etc/localtime:/etc/localtime:ro", read("docker-compose.yml"))

    def test_compose_never_leaves_the_time_zone_setting_empty(self):
        # An empty TZ means UTC to the system, which would undo the shared time zone file.
        compose = read("docker-compose.yml")
        self.assertIn("TZ=${TZ:-:/etc/localtime}", compose)
        self.assertNotIn("TZ=${TZ:-}", compose)

    def test_every_copied_path_exists(self):
        for dockerfile in ("Dockerfile", os.path.join("cloud", "Dockerfile")):
            for path in copied_into(dockerfile):
                self.assertTrue(os.path.exists(os.path.join(ROOT, path)), "%s copies missing %s" % (dockerfile, path))


class MacLauncher(unittest.TestCase):
    """The double-click launcher for the Mac, checked as text (it is not run)."""

    @classmethod
    def setUpClass(cls):
        cls.script = read("Start QuietNet.command")

    def test_the_launcher_recognises_apples_python_stand_in(self):
        # Without Apple's Command Line Tools, /usr/bin/python3 only offers to install them.
        self.assertIn("/usr/bin/xcode-select -p", self.script)
        self.assertIn("! apple_python_is_stub", self.script)

    def test_the_launcher_never_falls_back_to_apples_python_a_second_time(self):
        self.assertIn('[ "$OTHER" != /usr/bin/python3 ]', self.script)
        self.assertNotIn("PY=python3\n", self.script)

    def test_the_launcher_says_how_to_get_python_when_none_works(self):
        self.assertIn("https://www.python.org/downloads/", self.script)
        self.assertIn("xcode-select --install", self.script)

    def test_the_launcher_quotes_paths_that_may_contain_spaces(self):
        self.assertIn('cd "$(dirname "$0")"', self.script)
        self.assertIn('"$PY" server.py', self.script)


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

    def test_ids_and_counts_from_the_server_are_escaped_too(self):
        # Through the relay these come from a Pi the relay does not control, so even "numbers"
        # must not be pasted into the page raw.
        for raw in ('"${g.id}"', '"${x.id}"', '"${x.v}"', '"${x.on}"', "${g.services} service", "${g.members.length} device"):
            self.assertNotIn(raw, self.page, raw)

    def test_every_control_is_a_real_button_that_keyboards_can_reach(self):
        # A span playing a button inside a device card can't be reached with Tab, and Enter on
        # the card opens the device instead.
        self.assertNotIn('role="button"', self.page)

    def test_the_page_loads_nothing_from_other_websites(self):
        self.assertEqual(re.findall(r"""(?:src|href)=["']https?://""", self.page), [])

    def test_the_script_avoids_operators_that_older_safari_cannot_read(self):
        # '??' and '?.' are syntax errors before Safari 13.1, and one of them stops the whole script.
        script = self.page[self.page.index("<script>"):self.page.rindex("</script>")]
        for newer in ("??", "?."):
            self.assertNotIn(newer, script, newer)

    def test_the_page_spells_out_offsets_instead_of_using_inset(self):
        # Safari before 14.1 ignores 'inset', which left dialogs off-screen.
        self.assertNotIn("inset:", self.page)

    def test_the_timed_refresh_waits_for_the_last_one_and_for_a_visible_tab(self):
        timer = self.page[self.page.index("setInterval("):]
        timer = timer[:timer.index("\n")]
        self.assertIn("refreshFree()", timer)
        self.assertIn("!inFlight", self.page[self.page.index("const refreshFree"):][:120])
        self.assertIn("!document.hidden", timer)

    def test_a_stuck_refresh_does_not_stop_the_timer_for_good(self):
        free = self.page[self.page.index("const refreshFree"):]
        free = free[:free.index("\n")]
        self.assertIn("Date.now() - inFlightSince > STUCK_AFTER", free)
        self.assertIn("inFlightSince = Date.now()", self.page)
        self.assertIn("refreshFree()", self.page[self.page.index("'visibilitychange'"):][:100])

    def test_the_timed_refresh_fetches_the_activity_list_less_often(self):
        self.assertIn("tick && Date.now() - activityAt < ACTIVITY_EVERY", self.page)

    def test_the_activity_refresh_sends_back_the_last_marker(self):
        self.assertIn("&since=${encodeURIComponent(since)}", self.page)
        self.assertIn("S.activityKey === key ? S.activityMark : ''", self.page)

    def test_an_unchanged_activity_answer_keeps_the_list_shown(self):
        self.assertIn("if(!(x.unchanged && since)) S.activity = x.groups || [];", self.page)

    def test_opening_a_device_forgets_the_last_activity_marker(self):
        opener = self.page[self.page.index("open(d){"):]
        self.assertIn("S.activityKey = ''", opener[:opener.index("\n")])

    def test_the_page_says_when_a_scan_covered_only_part_of_the_network(self):
        self.assertIn("st.scan.capped", self.page)
        self.assertIn("Your network is large, so only the ${num(st.scan.addresses)} addresses", self.page)

    def test_the_page_spaces_flex_rows_with_margins_where_gap_is_ignored(self):
        self.assertIn("document.documentElement.className += ' nogap'", self.page)
        self.assertIn(".nogap .row>*", self.page)

    def test_the_enforcer_card_explains_ipv6_only_when_the_network_has_it(self):
        card = self.page[self.page.index("function enforceCard"):]
        card = card[:card.index("\nfunction ")]
        self.assertIn("((S.status || {}).ipv6 || {}).in_use ? `<p class=\"small muted\">This device's IPv6 connections "
                      "can't be cut directly; QuietNet stops giving it", card)
        self.assertIn("IPv6 addresses so it uses IPv4 instead. Connections it already had over IPv6 may carry on "
                      "for a short while.</p>` : ''", card)

    def test_the_enforcer_card_no_longer_says_it_works_on_ipv4_only(self):
        card = self.page[self.page.index("function enforceCard"):]
        card = card[:card.index("\nfunction ")]
        self.assertNotIn("It works on IPv4 only", card)


class DashboardFirewallNotice(unittest.TestCase):
    """The home page's notice when another firewall on the Pi stops "Cut live connections" for
    every device. These checks read the page's script; nothing is run in a browser."""

    @classmethod
    def setUpClass(cls):
        page = read("static", "index.html")
        cls.notice = page[page.index("function firewallNotice("):page.index("/* ---------- Devices that change address")]
        cls.home = page[page.index("function viewHome(){"):page.index("/* ---------- Another firewall in the way")]

    def test_the_firewall_notice_is_on_the_home_page(self):
        self.assertIn("${firewallNotice()}", self.home)

    def test_the_firewall_notice_is_shown_only_when_the_enforcer_reports_a_blocker(self):
        self.assertIn("((S.status || {}).enforcer || {}).firewall;", self.notice)
        self.assertIn("if(!fw || !(fw.commands || []).length) return '';", self.notice)

    def test_the_firewall_notice_escapes_the_names_and_the_command(self):
        self.assertIn("(fw.blocked_by || []).map(esc)", self.notice)
        self.assertIn("${esc(fw.commands.join(' && '))}", self.notice)

    def test_the_firewall_notice_says_the_command_lasts_until_the_next_restart(self):
        self.assertIn("A command run like this lasts until the next restart.", self.notice)

    def test_the_firewall_notice_says_the_install_command_makes_dockers_fix_permanent(self):
        self.assertIn("fw.installer ? 'Re-running the install command sets this up permanently.'", self.notice)


class DashboardIPv6Setup(unittest.TestCase):
    """"Set up a device" and the home page, on routers that hand out their own IPv6 DNS server.
    These checks read the page's script; nothing is run in a browser."""

    @classmethod
    def setUpClass(cls):
        page = read("static", "index.html")
        cls.setup = page[page.index("function viewSetup(){"):page.index("/* ---------- drawing & refreshing")]
        cls.warning = page[page.index("function v6Warning("):page.index("function viewSetup(){")]
        cls.home = page[page.index("function viewHome(){"):page.index("/* ---------- One device")]

    def step(self, title):
        """The script for one kind of device's steps on "Set up a device"."""
        start = self.setup.index("step('%s'" % title)
        return self.setup[start:self.setup.index("${step(", start + 1)]

    def test_the_setup_page_reads_the_ipv6_address_from_the_status(self):
        self.assertIn("const ip6 = esc(v6.dns_address || '');", self.setup)

    def test_the_windows_steps_give_the_ipv6_address_when_known(self):
        self.assertIn("Turn on <b>IPv6</b> and type <b>' + ip6 + '</b>", self.step("Windows PC"))

    def test_the_android_steps_give_the_ipv6_address_when_known(self):
        self.assertIn("' + ip6 + '</b> in <b>DNS 2</b>", self.step("Android phone or tablet"))

    def test_the_iphone_and_mac_steps_give_the_ipv6_address_when_known(self):
        self.assertIn("ip6", self.step("iPhone or iPad"))
        self.assertIn("ip6", self.step("Mac"))

    def test_the_setup_page_says_how_to_switch_ipv6_off_on_a_bt_hub(self):
        self.assertIn("<b>Advanced settings</b> → <b>IPv6</b>", self.setup)

    def test_without_an_ipv6_address_the_setup_page_says_to_switch_ipv6_off_or_accept_the_gap(self):
        self.assertIn("QuietNet has no IPv6 address to give devices", self.setup)
        self.assertIn("or accept that\n      some lookups will skip QuietNet", self.setup)

    def test_the_router_dns_warning_is_shown_only_for_servers_that_are_not_ours(self):
        self.assertIn(".router_dns_not_ours || []", self.warning)
        self.assertIn("if(!others.length) return '';", self.warning)

    def test_the_router_dns_warning_escapes_the_addresses(self):
        self.assertIn("esc(a)", self.warning)

    def test_the_router_dns_warning_says_what_to_do(self):
        self.assertIn("Your router tells devices to use its own IPv6 DNS server", self.warning)
        self.assertIn("Set QuietNet's IPv6 address as well, or switch IPv6 off on your router.", self.warning)

    def test_the_router_dns_warning_is_on_the_home_page_and_the_setup_page(self):
        self.assertIn("${v6Warning(true)}", self.home)
        self.assertIn("${v6Warning(false)}", self.setup)


class DashboardSharedAddresses(unittest.TestCase):
    """The device page's note that some of a blocked service's addresses are left to the name
    block because sites the device is allowed share them. Reads the page's script only."""

    @classmethod
    def setUpClass(cls):
        page = read("static", "index.html")
        cls.note = page[page.index("function sharedNote("):page.index("function enforceCard(")]
        cls.card = page[page.index("function enforceCard("):page.index("function statusBadges(")]

    def test_the_live_cut_card_shows_the_shared_address_note(self):
        self.assertIn("${sharedNote(d, e)}", self.card)

    def test_the_shared_address_note_escapes_the_names_and_the_count(self):
        self.assertIn(".map(esc)", self.note)
        self.assertIn("${num(sh.count)}", self.note)

    def test_the_shared_address_note_says_what_happened_in_plain_words(self):
        self.assertIn("addresses are shared with sites this device is allowed, so those connections are left to the name block", self.note)


class DashboardDeviceMoves(unittest.TestCase):
    """The dashboard's parts for devices that change address and for other DNS services: the
    "may be the same device" notices, recent changes to devices, the new-device group picker, the
    device badges and warning, and the other-DNS notice and switch. Device names, addresses and
    event notes come from the household network, so each must be escaped. Reads the page's
    script only; nothing is run in a browser."""

    @classmethod
    def setUpClass(cls):
        page = read("static", "index.html")
        cls.notices = page[page.index("function movedNotices("):page.index("function deviceWarning(")]
        cls.warning = page[page.index("function deviceWarning("):page.index("// What QuietNet did by itself")]
        cls.events = page[page.index("function deviceEvents("):page.index("/* ---------- One device")]
        cls.picker = page[page.index("function newDeviceCard("):page.index("function viewGroup(")]
        cls.other = page[page.index("function otherDnsNotice("):page.index("// Blocked things whose addresses")]
        cls.switch = page[page.index("function otherDnsSwitch("):page.index("/* ---------- Another firewall in the way")]
        cls.home = page[page.index("function viewHome(){"):page.index("// The household setting \"Stop every device")]
        cls.device = page[page.index("function viewDevice("):page.index("/* ---------- Groups")]
        cls.page = page

    def test_the_notices_are_on_the_home_page_and_the_device_page(self):
        self.assertIn("${movedNotices(null)}", self.home)
        self.assertIn("${movedNotices(d.ip)}", self.device)

    def test_the_notices_come_from_the_status_and_a_device_page_shows_only_its_own(self):
        self.assertIn("((S.status || {}).device_notices || []).filter(n => !ip || n.to === ip)", self.notices)

    def test_the_notices_escape_the_name_and_both_addresses(self):
        self.assertIn("${esc(n.name)}", self.notices)
        self.assertIn('data-from="${esc(n.from)}" data-to="${esc(n.to)}"', self.notices)
        self.assertIn('data-ip="${esc(n.to)}"', self.notices)
        self.assertNotIn("${n.", self.notices)

    def test_the_move_notice_offers_to_move_the_rules(self):
        self.assertIn('data-act="moverules"', self.notices)
        self.assertIn("Move the rules to this device", self.notices)

    def test_the_same_number_notice_asks_whether_it_is_the_same_device(self):
        self.assertIn("n.same", self.notices)
        self.assertIn("Yes, it's the same device", self.notices)
        self.assertIn('data-act="notsame"', self.notices)

    def test_the_different_device_answer_is_sent_to_the_pi(self):
        self.assertIn("api('/api/different-device', {ip:d.ip})", self.page)

    def test_the_device_warning_is_shown_only_when_there_is_one_and_is_escaped(self):
        self.assertIn("if(!d.warning) return '';", self.warning)
        self.assertIn("${esc(d.warning)}", self.warning)
        self.assertIn("${deviceWarning(d)}", self.device)

    def test_a_paused_device_can_be_confirmed_as_the_same_device_from_its_warning(self):
        self.assertIn("d.paused", self.warning)
        self.assertIn('data-from="${esc(d.ip)}" data-to="${esc(d.ip)}"', self.warning)

    def test_recent_changes_are_on_the_home_page_only_when_there_are_some(self):
        self.assertIn("${deviceEvents()}", self.home)
        self.assertIn("if(!ev.length) return '';", self.events)

    def test_recent_changes_escape_the_note_and_the_time(self):
        self.assertIn("${esc(e.text)} · ${esc(ago(e.ts))}", self.events)

    def test_the_new_device_group_picker_escapes_group_ids_and_names(self):
        self.assertIn('<option value="${esc(g.id)}"', self.picker)
        self.assertIn("${esc(g.name)}</option>", self.picker)
        self.assertIn("(S.status || {}).new_device_group", self.picker)

    def test_the_rules_paused_badge_shows_only_for_a_paused_device(self):
        self.assertIn("${d.paused ? '<span class=\"badge warn\">Rules paused</span>' : ''}", self.home)

    def test_the_other_dns_badge_shows_only_for_a_device_that_tried(self):
        self.assertIn("${d.other_dns ? '<span class=\"badge warn\">Tried another DNS service</span>' : ''}", self.home)

    def test_the_other_dns_notice_shows_only_when_the_device_tried_and_escapes_the_time(self):
        self.assertIn("if(!d.other_dns && !S.activity.some(g => g.other_dns)) return '';", self.other)
        self.assertIn("esc(ago(d.other_dns))", self.other)
        self.assertIn("${otherDnsNotice(d)}", self.device)

    def test_the_other_dns_switch_is_on_the_home_page_and_follows_the_status(self):
        self.assertIn("${otherDnsSwitch(st)}", self.home)
        self.assertIn("st.other_dns_all ? 'checked' : ''", self.switch)
        self.assertIn("api('/api/other-dns-switch', {on:e.target.checked})", self.page)

    def test_the_other_dns_switch_says_what_it_can_cut_off(self):
        self.assertIn("will then have no internet at home until its setting is changed", self.switch)


class DashboardThemes(unittest.TestCase):
    """The dashboard has three looks (calm, household, control), picked under Appearance and kept
    in the qn_theme cookie. These checks read the page; nothing is run in a browser."""

    THEMES = ("calm", "household", "control")

    @classmethod
    def setUpClass(cls):
        cls.page = read("static", "index.html")
        cls.css = cls.page[cls.page.index("<style>"):cls.page.index("</style>")]
        main = cls.page.index("const S = {")
        cls.main_script = cls.page[cls.page.rindex("<script>", 0, main):cls.page.rindex("</script>")]
        early = cls.page[:cls.page.index("<style>")]
        cls.early_script = early[early.index("<script>"):early.index("</script>")]

    def theme_from_cookie(self, cookie):
        """What the early script would pick for this cookie text, using its own pattern."""
        pattern = re.search(r"var m = /(.+?)/\.exec\(document\.cookie", self.early_script).group(1)
        m = re.search(pattern, cookie)
        return m.group(1) if m else "calm"

    def test_the_page_picks_its_theme_before_the_style_sheet_loads(self):
        self.assertIn("qn_theme", self.early_script)
        self.assertIn("setAttribute('data-theme'", self.early_script)

    def test_the_early_theme_script_accepts_only_the_three_themes(self):
        self.assertIn("qn_theme=(calm|household|control)", self.early_script)
        self.assertIn("m ? m[1] : 'calm'", self.early_script)

    def test_a_saved_theme_is_used(self):
        self.assertEqual(self.theme_from_cookie("a=1; qn_theme=control; b=2"), "control")
        self.assertEqual(self.theme_from_cookie("qn_theme=household"), "household")

    def test_an_unknown_theme_in_the_cookie_means_calm(self):
        for cookie in ("", "qn_theme=", "qn_theme=neon", "qn_theme=controlx", "qn_theme=\"><script>", "xqn_theme=control"):
            self.assertEqual(self.theme_from_cookie(cookie), "calm", cookie)

    def test_the_page_starts_in_the_calm_theme(self):
        self.assertIn('<html lang="en" data-theme="calm">', self.page)

    def test_each_theme_has_its_own_colours(self):
        self.assertIn(':root, [data-theme="calm"]{', self.css)
        for theme in ("household", "control"):
            block = self.css[self.css.index('[data-theme="%s"]{' % theme):]
            self.assertIn("--accent:", block[:block.index("}")], theme)

    def test_the_light_and_dark_themes_follow_the_device_setting(self):
        darks = re.findall(r"@media \(prefers-color-scheme: dark\)\{\s*([^{]+)\{", self.css)
        self.assertEqual(len(darks), 2)
        self.assertIn(':not([data-theme="household"]):not([data-theme="control"])', darks[0])
        self.assertIn('[data-theme="household"]', darks[1])
        control = self.css[self.css.index('[data-theme="control"]{'):]
        self.assertIn("color-scheme:dark", control[:control.index("}")])

    def test_the_appearance_section_offers_the_three_themes(self):
        self.assertIn('name="qnTheme"', self.main_script)
        choices = self.main_script[self.main_script.index("const THEME_CHOICES"):]
        choices = choices[:choices.index("]];")]
        self.assertEqual(tuple(re.findall(r"\['(\w+)', '", choices)), self.THEMES)
        self.assertIn("const THEMES = ['calm', 'household', 'control'];", self.main_script)

    def test_the_header_has_a_way_to_the_appearance_section(self):
        self.assertIn('data-act="appearance"', self.page)
        self.assertIn("appearance(){", self.main_script)
        self.assertIn('id="appearance"', self.main_script)

    def test_picking_a_theme_switches_at_once_without_asking_the_server(self):
        listener = self.main_script[self.main_script.index("e.target.name === 'qnTheme'"):]
        self.assertIn("setTheme(e.target.value)", listener[:listener.index("\n")])
        set_theme = self.main_script[self.main_script.index("function setTheme"):]
        set_theme = set_theme[:set_theme.index("\n}")]
        self.assertNotIn("api(", set_theme)
        self.assertIn("if(THEMES.indexOf(t) < 0) t = 'calm';", set_theme)

    def test_the_theme_choice_is_kept_for_a_year_across_the_site(self):
        set_theme = self.main_script[self.main_script.index("function setTheme"):]
        set_theme = set_theme[:set_theme.index("\n}")]
        for part in ("'qn_theme=' + t", "Path=/", "Max-Age=31536000", "SameSite=Lax", "'; Secure'"):
            self.assertIn(part, set_theme)

    def test_the_page_loads_no_fonts_from_other_websites(self):
        for outside in ("@import", "fonts.googleapis", "url(http", "@font-face", "http://", "https://"):
            self.assertNotIn(outside, self.page, outside)

    def test_the_views_carry_no_fixed_colours(self):
        # Colours live in the theme blocks of the style sheet; the markup only names classes.
        self.assertNotIn('style="', self.page)
        self.assertEqual(re.findall(r"#[0-9a-fA-F]{6}\b", self.main_script), [])

    def test_the_head_and_body_tags_stay_bare(self):
        # The relay finds these with a plain text replace, so neither may carry attributes.
        self.assertEqual(re.findall(r"<head\b[^>]*>", self.page, flags=re.I), ["<head>"])
        self.assertEqual(re.findall(r"<body\b[^>]*>", self.page, flags=re.I), ["<body>"])

    def test_the_relay_bar_colours_are_defined_by_every_theme(self):
        for token in ("--bar-bg:", "--bar-ink:", "--bar-muted:", "--bar-line:", "--bar-dot:"):
            self.assertEqual(self.css.count(token), 5, token)   # calm, calm dark, household, household dark, control

    def test_icons_are_hidden_from_screen_readers(self):
        for tag in re.findall(r"<svg[^>]*>", self.page):
            self.assertIn('aria-hidden="true"', tag)

    def rule(self, selector):
        """The declarations of the style rule whose selector list is exactly this text."""
        m = re.search(r"(?:^|[}\n])\s*" + re.escape(selector) + r"\{([^}]*)\}", self.css)
        self.assertIsNotNone(m, selector)
        return m.group(1)

    def test_the_focus_ring_on_a_row_in_a_clipped_list_is_drawn_inside_the_row(self):
        for theme in ("calm", "control"):
            self.assertIn("overflow:hidden", self.rule('[data-theme="%s"] .tiles' % theme))
        body = self.rule('[data-theme="calm"] .tiles .tile:focus-visible,[data-theme="control"] .tiles .tile:focus-visible')
        self.assertIn("outline-offset:calc(-1 * var(--focus-w) - 2px)", body)

    def test_household_gives_the_whole_width_to_the_page_when_the_house_controls_are_hidden(self):
        body = self.rule('[data-theme="household"] .shell.no-house')
        self.assertIn("grid-template-columns:minmax(0,1fr)", body)
        self.assertNotIn("house", body.split("grid-template-areas:")[1])

    def test_the_control_room_only_sets_the_address_line_in_monospace(self):
        self.assertNotIn('[data-theme="control"] .pagehead .meta{', self.css)
        self.assertIn("font-family:var(--font-mono)", self.rule('[data-theme="control"] .pagehead .meta:not(.sugg)'))

    def test_the_control_room_stacks_its_figures_above_the_house_controls_below_laptop_width(self):
        m = re.search(r"@media \(max-width:(\d+)px\)\{\s*\[data-theme=\"control\"\] \.shell\{", self.css)
        self.assertIsNotNone(m)
        self.assertGreaterEqual(int(m.group(1)), 1180)

    def test_household_leaves_room_under_the_header_for_the_focus_ring(self):
        body = self.rule('[data-theme="household"] .shell>.top')
        pad = re.search(r"padding:\d+px \d+(?:px)? (\d+)px", body)
        self.assertGreaterEqual(int(pad.group(1)), 6)


class Readme(unittest.TestCase):
    def test_the_readme_does_not_send_people_to_an_address_that_is_refused(self):
        # The dashboard answers on localhost only (see test_dashboard_api.Guards).
        self.assertNotIn("address>:8377`", read("README.md"))
        self.assertIn("http://localhost:8377", read("README.md"))

    def test_every_top_level_file_is_listed_in_the_readme(self):
        readme = read("README.md")
        for name in ("server.py", "names.py", "enforcer.py", "cloud_agent.py", "services.json", "junk_domains.txt",
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
