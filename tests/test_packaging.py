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
import tempfile
import unittest

# Before server is imported, as in test_quietnet.py: server settles on its data folder when it is
# first imported. Without this, naming a class from this file ahead of one built on
# test_quietnet.Base would aim that class's clean-up at the checkout's own data folder (or at
# whatever folder the person running the tests has in QUIETNET_DATA).
if "server" not in sys.modules:
    os.environ["QUIETNET_DATA"] = tempfile.mkdtemp(prefix="quietnet-test-")
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


class NeededNames(unittest.TestCase):
    """The short list of names a device's own system depends on (server.NEEDED). It decides a label
    and a question, so it must stay short, sure and keyed the way the activity list groups names."""

    def test_needed_names_are_keyed_by_addresses_the_grouping_can_produce(self):
        for d in server.NEEDED:
            self.assertEqual(server.base_of(d), d, "%r can never match: activity is grouped as %r" % (d, server.base_of(d)))

    def test_needed_names_are_well_formed_lower_case_addresses(self):
        for d in server.NEEDED:
            self.assertTrue(server.VALID_NAME.fullmatch(d), repr(d))

    def test_both_of_samsungs_tv_names_are_needed(self):
        self.assertEqual((server.NEEDED["samsungcloudsolution.com"], server.NEEDED["samsungcloudsolution.net"]),
                         ("Samsung TVs", "Samsung TVs"))

    def test_the_list_stays_short_enough_to_be_believed(self):
        # A long list would put the question in front of people so often that they stop reading it.
        self.assertTrue(20 <= len(server.NEEDED) <= 40, len(server.NEEDED))

    def test_no_needed_name_is_on_the_built_in_advert_list(self):
        junk = {l.strip() for l in read("junk_domains.txt").splitlines() if l.strip() and not l.startswith("#")}
        self.assertEqual([d for d in server.NEEDED if d in junk], [])

    def test_who_needs_each_name_is_a_short_plain_phrase(self):
        for d, who in server.NEEDED.items():
            self.assertTrue(re.fullmatch(r"[A-Z][A-Za-z ]{3,40}", who), (d, who))

    def test_samsungs_second_tv_name_has_an_owner_label(self):
        self.assertEqual(server.OWNERS["samsungcloudsolution.net"], "Samsung TV")

    def test_the_name_behind_a_samsung_tvs_online_check_and_set_up_is_needed(self):
        self.assertEqual(server.NEEDED["samsungqbe.com"], "Samsung TVs")

    def test_the_name_behind_a_samsung_tvs_online_check_has_an_owner_label(self):
        self.assertEqual(server.OWNERS["samsungqbe.com"], "Samsung TV")

    def test_the_name_behind_an_lg_tvs_updates_is_needed(self):
        self.assertEqual(server.NEEDED["lge.com"], "LG TVs")

    def test_one_lg_update_sub_name_is_not_itself_needed(self):
        # Blocking snu.lge.com alone is a common, deliberate way to hold back updates: it must not ask.
        self.assertEqual(server.needed_by("snu.lge.com"), "")


class TestDataFolder(unittest.TestCase):
    """Tests never touch the real data folder. server.py settles on its folder when it is first
    imported, so a test file that imports it must name a throwaway folder first; otherwise the
    order in which test classes are named on the command line decides whose data gets cleared."""

    def test_every_test_file_that_imports_server_names_a_throwaway_data_folder_first(self):
        here = os.path.join(ROOT, "tests")
        for name in sorted(os.listdir(here)):
            if not name.endswith(".py"):
                continue
            lines = read("tests", name).splitlines()
            imports = [i for i, line in enumerate(lines) if re.match(r"(import|from) server\b", line)]
            if not imports:
                continue
            folder = [i for i, line in enumerate(lines)
                      if line.strip().startswith('os.environ["QUIETNET_DATA"] = tempfile.mkdtemp(')]
            self.assertTrue(folder and folder[0] < imports[0], name)

    def test_the_data_folder_these_tests_use_is_not_the_checkouts_own(self):
        self.assertNotEqual(os.path.realpath(server.DATA), os.path.realpath(os.path.join(ROOT, "data")))


class DashboardNeededNames(unittest.TestCase):
    """The dashboard's parts for names a device's own system depends on: the "Needed by" note in
    place of "Possibly junk", the question before blocking one, and the note beside a block that
    already exists. Reads the page's script only; nothing is run in a browser."""

    @classmethod
    def setUpClass(cls):
        page = read("static", "index.html")
        cls.helpers = page[page.index("function neededQuestion("):page.index("function statusBadges(")]
        cls.block_address = page[page.index("async function blockAddress("):page.index("function statusBadges(")]
        cls.badges = page[page.index("function statusBadges("):page.index("function blockedByYouNote(")]
        cls.button = page[page.index("function blockBtn("):page.index("function activityList(")]
        cls.activity = page[page.index("function activityList("):page.index("function viewDevice(")]
        cls.rules = page[page.index("function viewRules("):page.index("/* ---------- Set up a device")]
        cls.api = page[page.index("async function api("):page.index("function ago(")]
        cls.ask = page[page.index("function ask("):page.index("const oops =")]
        cls.page = page

    def test_a_needed_name_shows_who_needs_it(self):
        self.assertIn("Needed by ${esc(x.needed)}", self.badges)

    def test_a_needed_name_is_never_called_possibly_junk(self):
        # "Possibly junk" is the 'else' of the needed check, so the two can never show together.
        needed = self.badges.index("if(x.needed) out +=")
        junk = self.badges.index('<span class="badge warn">Possibly junk</span>')
        self.assertLess(needed, junk)
        self.assertIn("else if(x.v === 'suspect') out +=", self.badges[needed:junk])
        self.assertEqual(self.page.count("Possibly junk</span>"), 1)

    def test_a_name_on_the_advert_list_keeps_its_advert_label(self):
        self.assertIn("if(x.v === 'junk') out += '<span class=\"badge danger\">Advert / tracker</span>';", self.badges)

    def test_the_block_button_on_a_needed_name_is_not_the_highlighted_one(self):
        self.assertIn("x.v === 'ok' || x.needed ? '' : 'primary'", self.button)

    def test_the_question_says_who_needs_the_address_and_what_may_happen(self):
        self.assertIn("${who} need this address for their own system to work. Blocking it may stop them opening apps, "
                      "signing in or updating. Block it anyway?", self.helpers)

    def test_the_question_promises_nothing(self):
        self.assertNotIn("will stop", self.helpers)

    def test_the_question_is_asked_only_when_the_server_says_the_name_is_needed(self):
        self.assertIn("if(e.status !== 409 || !a.needed) throw e;", self.block_address)

    def test_the_question_goes_through_the_pop_up_that_escapes_its_text(self):
        self.assertIn("ask({title:`Block ${a.domain || domain}?`, ok:'Block it anyway', danger:true, careful:true, "
                      "text:neededQuestion(a.needed)})", self.block_address)

    def test_a_needed_name_is_asked_one_question_not_two(self):
        # The general "this doesn't look like an advert or tracker" question is skipped for a
        # needed name, which gets the fuller one. The button carries who needs the name (checked
        # in test_who_needs_a_name_is_escaped_wherever_it_is_shown), so d.needed is filled.
        self.assertIn("if(d.v === 'ok' && !d.needed){", self.page)

    # ----- a second Enter, or a held one, must not answer yes

    def test_the_question_puts_the_keyboard_on_cancel(self):
        self.assertIn("(input !== undefined ? $('mInput') : careful && cancel ? $('mNo') : $('mYes')).focus();", self.ask)

    def test_enter_does_not_answer_yes_to_a_careful_question_from_anywhere_in_it(self):
        # Enter then presses only the button the keyboard is on, which starts as Cancel.
        self.assertIn("if(e.key === 'Enter' && !careful) $('mYes').click();", self.ask)

    def test_a_question_is_careful_only_when_asked_to_be(self):
        self.assertIn("cancel='Cancel', careful=false}){", self.ask)
        self.assertEqual(self.page.count("careful:true"), 1)

    def test_a_held_down_enter_never_answers_a_question(self):
        held = self.ask.index("if(e.key === 'Enter' && e.repeat){ e.preventDefault(); return; }")
        self.assertLess(held, self.ask.index("$('mYes').click()"))

    def test_a_held_down_enter_sends_a_typed_name_only_once(self):
        self.assertIn("if(e.key === 'Enter' && !e.repeat && e.target.id === 'addBox') actions.add();", self.page)

    def test_saying_no_blocks_nothing(self):
        self.assertIn("if(!yes) return false;", self.block_address)

    def test_saying_yes_sends_the_block_again_marked_sure(self):
        asked, sure = self.block_address.index("await ask("), self.block_address.index("{domain:domain, sure:true}")
        self.assertLess(asked, sure)

    def test_every_way_of_blocking_an_address_goes_through_the_question(self):
        # The Block button on a device page and the box on the Blocked list page. Nothing else on
        # the page may call the block address directly.
        self.assertEqual(self.page.count("'/api/block'"), self.block_address.count("'/api/block'"))
        self.assertIn("await blockAddress(d.d).catch(oops)", self.page)
        self.assertIn("if(await blockAddress(v))", self.page)

    def test_a_refusal_carries_its_status_and_answer_to_the_caller(self):
        self.assertIn("e.status = r.status; e.answer = j;", self.api)

    def test_the_note_beside_an_existing_block_says_who_needs_it_and_what_to_do(self):
        self.assertIn("${esc(who)} need this address. If apps have stopped opening on one, or it can't sign in or "
                      "update, unblock it.", self.helpers)

    def test_a_blocked_name_nobody_needs_carries_no_note(self):
        self.assertIn("return who ? `<div class=\"meta\">${esc(who)} need this address.", self.helpers)
        self.assertIn("unblock it.</div>` : '';", self.helpers)

    def test_the_blocked_list_page_carries_the_note(self):
        self.assertIn("${blocks ? neededBlockedNote(x.needed) : ''}", self.rules)
        self.assertIn("rows(r.blocked, 'Unblock', true)", self.rules)

    def test_the_always_allowed_list_does_not_carry_the_note(self):
        self.assertIn("rows(r.allowed, 'Remove', false)", self.rules)

    def test_a_blocked_by_you_row_on_a_device_page_carries_the_note(self):
        self.assertIn("function blockedByYouNote(x){ return x.b && x.why === 'you' ? neededBlockedNote(x.needed) : ''; }", self.page)
        self.assertIn("${blockedByYouNote(g)}", self.activity)
        self.assertIn("${blockedByYouNote(h)}", self.activity)

    def test_who_needs_a_name_is_escaped_wherever_it_is_shown(self):
        for part in (self.helpers, self.badges, self.button, self.activity, self.rules):
            self.assertNotIn("${x.needed}", part)
        # The one unescaped use builds the question's text, which ask() escapes when it shows it.
        self.assertEqual(self.helpers.count("${who}"), 1)
        self.assertIn("return `${who} need this address for their own system to work.", self.helpers)
        self.assertIn('data-needed="${esc(x.needed || \'\')}"', self.button)
        self.assertIn("Needed by ${esc(x.needed)}", self.rules)


class DashboardContract(unittest.TestCase):
    """The dashboard page is served twice: by the Pi directly, and by the relay, which
    edits it on the way through. These checks protect the things each side relies on."""

    @classmethod
    def setUpClass(cls):
        cls.page = read("static", "index.html")

    def test_every_api_address_the_dashboard_calls_exists_on_the_server(self):
        # Digits are allowed in a call's name (/api/no-ipv6-switch); without them here the name
        # would be cut short at the digit and the check would compare the wrong thing.
        called = set(re.findall(r"""['"`](/api/[a-z0-9-]+)""", self.page))
        self.assertGreater(len(called), 15)
        self.assertIn("/api/no-ipv6-switch", called)
        handled = set(re.findall(r"""["'](/api/[a-z0-9-]+)["']""", read("server.py")))
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
        self.assertIn("((S.status || {}).ipv6 || {}).in_use ? `<p class=\"small muted\">This covers IPv4 only, "
                      "and IPv6 is on in your home.", card)
        self.assertIn("are not seen or cut.</p>` : ''", card)

    def test_the_enforcer_card_says_plainly_what_still_gets_out_over_ipv6(self):
        card = self.page[self.page.index("function enforceCard"):]
        card = card[:card.index("\nfunction ")]
        self.assertIn("But lookups the device sends to the router's\n      own IPv6 DNS server, and anything it reaches "
                      "over IPv6, are not seen or cut.", card)
        self.assertNotIn("so it uses IPv4 instead", card)             # the old wording promised too much

    def test_the_enforcer_card_says_ipv4_only_just_once_and_only_when_the_network_has_ipv6(self):
        card = self.page[self.page.index("function enforceCard"):]
        card = card[:card.index("\nfunction ")]
        self.assertEqual(card.count("IPv4 only"), 1)
        self.assertIn(".in_use ? `<p class=\"small muted\">This covers IPv4 only", card)
        self.assertNotIn("It works on IPv4 only", card)      # the old sentence, shown to every home


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


class DashboardIPv6Honesty(unittest.TestCase):
    """What the dashboard says about IPv6: the router steps, the "IPv6 is off on your hub"
    confirmation, the optional switch, and which devices can bypass QuietNet. These checks read
    the page's script; nothing is run in a browser."""

    @classmethod
    def setUpClass(cls):
        cls.page = read("static", "index.html")
        cls.setup = cls.page[cls.page.index("function viewSetup(){"):cls.page.index("/* ---------- drawing & refreshing")]
        cls.home = cls.page[cls.page.index("function viewHome(){"):cls.page.index("// The household setting \"Stop every device")]
        cls.device = cls.page[cls.page.index("function viewDevice(){"):]

    def part(self, name):
        """The script of one function on the page."""
        start = self.page.index("function %s(" % name)
        return self.page[start:self.page.index("\nfunction ", start + 1)]

    def test_the_setup_page_says_how_to_switch_allocation_mode_off(self):
        self.assertIn("step('Best: switch IPv6 off on the hub'", self.setup)
        self.assertIn("<b>Advanced Settings</b> → <b>IPv6</b> → <b>Configuration</b>", self.setup)
        self.assertIn("Set <b>Allocation Mode</b> to <b>Off</b> and save.", self.setup)

    def test_the_setup_page_says_to_switch_ula_on_when_there_is_no_off(self):
        self.assertIn("step('If there is no Off: switch ULA on'", self.setup)
        self.assertIn("turn on <b>ULA Enabled</b> and save", self.setup)

    def test_the_setup_page_says_what_to_do_after_switching_ipv6_off(self):
        for must in ("<b>Afterwards:</b> turn Wi-Fi off and on again on each device, or restart it.",
                     "games consoles (party chat) and work laptops (a work VPN)",
                     "Come back to this page in about an hour. It says <b>IPv6 is off on your hub</b>"):
            self.assertIn(must, self.setup)

    def test_the_setup_page_says_what_to_do_after_switching_ula_on(self):
        self.assertIn("<b>Afterwards:</b> within a few minutes the IPv6 number below changes to one starting <b>fd</b>", self.setup)
        self.assertIn("Set that number as the IPv6 DNS server on each device", self.setup)

    def test_the_setup_page_is_honest_that_ula_does_not_close_the_gap(self):
        self.assertIn("This narrows the gap but does not close it", self.setup)

    def test_both_router_changes_say_how_to_undo_them(self):
        self.assertIn("To undo it, set <b>Allocation Mode</b> back to what it was.", self.setup)
        self.assertIn("To undo it, turn <b>ULA Enabled</b> off again.", self.setup)

    def test_the_ipv6_off_confirmation_shows_only_when_the_pi_says_so(self):
        state = self.part("hubIpv6State")
        self.assertIn("if(v6.hub_off) return `<div class=\"notice info\"><b>IPv6 is off on your hub.</b>", state)
        self.assertEqual(self.page.count("<b>IPv6 is off on your hub.</b>"), 1)
        self.assertIn("${hubIpv6State(v6)}", self.setup)

    def test_while_ipv6_is_on_the_setup_page_says_devices_can_bypass(self):
        self.assertIn("if(v6.in_use) return `<div class=\"notice warn\"><b>IPv6 is on in your home.</b>", self.part("hubIpv6State"))

    def test_a_pi_that_is_not_listening_says_it_cannot_tell_rather_than_all_clear(self):
        state = self.part("hubIpv6State")
        self.assertIn("if(!v6.listening || v6.listening_for == null) return `<p class=\"meta\">QuietNet can't tell from here "
                      "whether IPv6 is on.", state)
        self.assertLess(state.index("if(!v6.listening"), state.index("Still checking"))

    def test_the_setup_page_says_when_something_still_names_an_ipv6_dns_server_that_is_not_quietnet(self):
        state = self.part("hubIpv6State")
        self.assertIn("if((v6.router_dns_not_ours || []).length) return `<div class=\"notice warn\"><b>Something in your "
                      "home still names an IPv6\n    DNS server that is not QuietNet</b>", state)
        self.assertIn("so QuietNet can't say IPv6 is off", state)
        self.assertIn("They are marked \"Can bypass over IPv6\"\n    on the Devices page.", state)

    def test_the_named_ipv6_dns_servers_are_escaped_on_the_setup_page(self):
        self.assertIn("${v6.router_dns_not_ours.map(a => '<b>' + esc(a) + '</b>').join(', ')}", self.part("hubIpv6State"))

    def test_a_named_ipv6_dns_server_is_reported_after_off_and_on_and_before_still_checking(self):
        state = self.part("hubIpv6State")
        order = [state.index(mark) for mark in ("if(v6.hub_off)", "if(v6.in_use)", "if((v6.router_dns_not_ours || []).length)",
                                                "if(!v6.listening", "Still checking")]
        self.assertEqual(order, sorted(order))

    def test_a_pi_with_its_own_ipv6_switched_off_says_it_cannot_tell_rather_than_still_checking(self):
        state = self.part("hubIpv6State")
        self.assertIn("if(v6.can_hear === false) return `<div class=\"notice warn\"><b>QuietNet can't tell whether IPv6 is on "
                      "in your home.</b>\n    IPv6 is switched off on this computer's own network connection, so it can't hear "
                      "your router's IPv6 announcements.", state)
        self.assertIn("switch IPv6 back on for the\n    Raspberry Pi itself", state)
        self.assertLess(state.index("if(v6.can_hear === false)"), state.index("Still checking"))

    def test_a_pi_that_could_not_find_out_whether_it_can_hear_says_it_cannot_tell_yet(self):
        state = self.part("hubIpv6State")
        self.assertIn("if(v6.can_hear === null) return `<p class=\"meta\"><b>QuietNet can't tell yet whether IPv6 is on.</b>", state)
        self.assertLess(state.index("if(v6.can_hear === null)"), state.index("Still checking"))

    def test_an_older_pi_that_does_not_say_whether_it_can_hear_is_shown_what_it_always_was(self):
        state = self.part("hubIpv6State")
        self.assertNotIn("can_hear == ", state)                # a missing answer must not be read as "no" or "not known"
        self.assertNotIn("!v6.can_hear", state)

    def test_an_older_pi_reached_through_the_relay_is_not_offered_a_switch_it_does_not_have(self):
        self.assertIn("if(st.no_ipv6_all == null) return '';", self.part("noIpv6Switch"))

    def test_while_checking_the_page_says_how_long_is_left_and_escapes_the_number(self):
        state = self.part("hubIpv6State")
        self.assertIn("Math.ceil((3600 - (v6.listening_for || 0)) / 60)", state)
        self.assertIn("num(left)", state)
        self.assertIn("Restarting QuietNet starts the hour again.", state)

    def test_the_no_ipv6_switch_is_on_the_setup_page_and_follows_the_status(self):
        self.assertIn("${noIpv6Switch(S.status || {})}", self.setup)
        self.assertIn("st.no_ipv6_all ? 'checked' : ''", self.part("noIpv6Switch"))
        self.assertIn("api('/api/no-ipv6-switch', {on:e.target.checked})", self.page)

    def test_the_no_ipv6_switch_says_it_is_off_by_default_and_what_it_can_break(self):
        switch = self.part("noIpv6Switch")
        for must in ("Off unless you turn it on.", "a site that works over IPv6 only would stop working",
                     "Names of things in your own home are not\n      affected.", "Turn it off again at any time"):
            self.assertIn(must, switch)

    def test_the_bypass_badge_shows_only_for_a_device_the_pi_marks_and_that_uses_quietnet(self):
        self.assertIn("function v6Bypass(d){ return !!(d.v6_bypass && d.last); }", self.page)
        self.assertIn("${v6Bypass(d) ? '<span class=\"badge warn\">Can bypass over IPv6</span>' : ''}", self.home)

    def test_the_device_page_says_the_device_can_bypass_quietnet_over_ipv6(self):
        notice = self.part("v6BypassNotice")
        self.assertIn("if(!v6Bypass(d)) return '';", notice)
        self.assertIn("<b>This device can bypass QuietNet over IPv6.</b>", notice)
        self.assertIn("The sure fix is to switch IPv6 off on your router.", notice)
        self.assertIn("${v6BypassNotice(d)}", self.device)

    def test_the_device_page_says_ipv6_is_on_in_your_home_only_when_the_pi_says_so(self):
        notice = self.part("v6BypassNotice")
        self.assertIn("((S.status || {}).ipv6 || {}).in_use\n    ? `IPv6 is on in your home, and your router gives every "
                      "device its own IPv6 DNS server.", notice)
        self.assertIn(": `Something in your home, most likely your router, tells every device to use an IPv6 DNS server "
                      "that is not\n    QuietNet.", notice)
        self.assertEqual(notice.count("IPv6 is on in your home"), 1)

    def test_the_device_page_says_cut_live_connections_does_not_close_the_ipv6_gap(self):
        self.assertIn("${d.enforced ? ' \"Cut live connections\" covers IPv4 only, so it does not close this.' : ''}",
                      self.part("v6BypassNotice"))

    def test_the_same_device_hint_is_escaped_and_says_no_rules_are_applied(self):
        self.assertIn("Probably the same device as ${esc(sameAsName(d))}", self.part("sameAsLine"))
        notice = self.part("sameAsNotice")
        self.assertIn("<b>${esc(sameAsName(d))}</b>", notice)
        self.assertIn('data-act="open" data-device="${esc(keyOf(sameAsCard(d)))}"', notice)
        self.assertIn("so that device's rules are not applied here", notice)
        self.assertIn("${sameAsNotice(d)}", self.device)

    def test_the_home_page_says_when_ipv6_lookups_cannot_be_matched_to_devices(self):
        notice = self.part("v6NeighbourNotice")
        self.assertIn("if(v6.neighbours_ok !== false || !v6.taking_lookups) return '';", notice)
        self.assertIn("<b>QuietNet can't tell which device a lookup over IPv6 came from.</b>", notice)
        self.assertIn("${v6NeighbourNotice()}", self.home)

    def test_the_router_card_is_put_on_the_setup_page(self):
        shown = self.setup[self.setup.index("const hubCard = `"):]
        self.assertEqual(shown.count("${hubCard}"), 1)
        self.assertIn("${hubCard}", shown[shown.index("  return `"):])

    def test_the_home_page_shows_the_same_device_hint_on_a_device(self):
        self.assertIn("${sameAsLine(d)}", self.home)

    def test_the_page_no_longer_says_rules_do_not_follow_a_device_to_a_new_number(self):
        self.assertNotIn("won't follow it", self.page)
        self.assertNotIn("Devices are recognised by their number", self.page)
        self.assertIn("<b>Devices are recognised by their hardware address</b>", self.setup)
        self.assertIn("its name, group and blocks follow it within a minute or so", self.setup)

    def test_the_page_says_hardware_address_not_mac_to_people(self):
        shown = re.sub(r"\$\{[^}]*\}", "", self.setup + self.part("v6BypassNotice") + self.part("sameAsNotice")
                       + self.part("hubIpv6State") + self.part("noIpv6Switch") + self.part("v6NeighbourNotice"))
        self.assertNotRegex(shown, r"\bMAC\b")


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
        self.assertIn("${movedNotices(S.device)}", self.device)

    def test_the_notices_come_from_the_status_and_a_device_page_shows_only_its_own(self):
        # A device's page shows the questions it is part of, as the newcomer or as the device the
        # rules belong to. A card is known by its key (the device's number, else its address).
        self.assertIn("((S.status || {}).device_notices || []).filter(n => !key || aboutCard(n, key))", self.notices)
        self.assertIn("const noticeKey = n => n.to_device == null ? 'a' + n.to : 'd' + n.to_device;", self.page)
        self.assertIn("const aboutCard = (n, key) => noticeKey(n) === key || "
                      "(n.from_device != null && 'd' + n.from_device === key);", self.page)

    def test_a_notice_opens_the_newcomers_card_by_its_key(self):
        self.assertIn('data-act="open" data-device="${esc(noticeKey(n))}"', self.notices)

    def test_the_notices_escape_the_name_and_both_addresses(self):
        self.assertIn("${esc(n.name)}", self.notices)
        self.assertIn('data-from="${esc(n.from)}" data-to="${esc(n.to)}"', self.notices)
        self.assertIn('data-ip="${esc(n.to)}"', self.notices)
        self.assertNotIn("${n.", self.notices)

    def test_the_gone_quiet_notice_offers_to_say_it_is_the_same_device(self):
        self.assertIn('data-act="moverules"', self.notices)
        self.assertIn("has gone quiet and a new device appeared", self.notices)
        self.assertIn(">It's the same device</button>", self.notices)

    def test_the_notices_send_back_the_two_devices_numbers_when_the_pi_gave_them(self):
        self.assertIn('n.to_device == null ? \'\' : ` data-todev="${esc(n.to_device)}" data-fromdev="${esc(n.from_device)}"`',
                      self.notices)
        self.assertIn("if(d.todev){ body.to_device = d.todev; body.from_device = d.fromdev; }", self.page)

    def test_a_number_now_behind_a_range_extender_offers_only_the_answer_no(self):
        part = self.notices[self.notices.index("n.same && n.extender"):self.notices.index(": n.same && n.held")]
        self.assertIn("now connects through a Wi-Fi range extender", part)
        self.assertIn('data-act="notsame"', part)
        self.assertNotIn('data-act="moverules"', part)

    def test_rules_kept_under_a_number_alone_get_a_notice_of_their_own(self):
        self.assertIn("n.same && n.held", self.notices)
        self.assertIn("Are they for this device?", self.notices)

    def test_saying_it_is_the_same_device_says_the_two_become_one_and_what_gives_way(self):
        self.assertIn("The two become one device from now on", self.page)
        self.assertIn("If both are in a group, it keeps the group of the device the rules belong to", self.page)
        self.assertIn("No block, schedule or switch either had is dropped.", self.page)
        self.assertNotIn("Nothing either had is dropped", self.page)

    def test_the_same_number_notice_asks_whether_it_is_the_same_device(self):
        self.assertIn("n.same", self.notices)
        self.assertIn("Yes, it's the same device", self.notices)
        self.assertIn('data-act="notsame"', self.notices)

    def test_the_different_device_answer_is_sent_to_the_pi(self):
        self.assertIn("api('/api/different-device', d.todev ? {ip:d.ip, device:d.todev} : {ip:d.ip})", self.page)

    def test_the_device_warning_is_shown_only_when_there_is_one_and_is_escaped(self):
        self.assertIn("if(!d.warning) return '';", self.warning)
        self.assertIn("${esc(d.warning)}", self.warning)
        self.assertIn("${deviceWarning(d)}", self.device)

    def test_a_paused_device_can_be_confirmed_as_the_same_device_from_its_warning(self):
        self.assertIn("d.paused", self.warning)
        self.assertIn('data-act="samehere" data-ip="${esc(d.ip)}"', self.warning)
        self.assertIn("api('/api/move-rules', {from:d.ip, to:d.ip})", self.page)

    def test_the_paused_cards_question_says_the_rules_apply_again_not_that_two_devices_are_joined(self):
        asked = self.page[self.page.index("async samehere(d){"):self.page.index("// \"No, it's a different device\"")]
        self.assertIn("they will apply to it again", asked)
        self.assertNotIn("become one device", asked)

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
