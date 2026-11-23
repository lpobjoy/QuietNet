"""Checks for install.sh, the one-line installer for a Raspberry Pi or other Linux computer.

Run with:  python3 -m unittest tests.test_installer

The installer is run for real, with /bin/sh (and with dash or busybox too where this computer
has them), but its PATH holds only stand-in commands: docker, curl, wget, sudo, id, uname, ss,
sysctl, systemctl, hostname, ip and sleep are small scripts that write down how they were called
and answer as each test asks. Ordinary tools (tar, cp, mv and so on) are the real ones, reached
through links. Nothing is downloaded, no real Docker or firewall command is run, and nothing
outside a throwaway folder is changed: QUIETNET_SYSROOT moves /etc into that folder.
"""
import io
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "install.sh")

# Real tools the installer may call, reached through links in the stand-in folder.
REAL_TOOLS = ["sh", "env", "mktemp", "tar", "gzip", "cp", "mv", "rm", "mkdir", "chmod", "cat", "sed",
              "awk", "tr", "grep", "sort", "head", "tee", "dirname", "ls", "ln", "readlink", "touch", "date",
              "test", "true"]

STUBS = {
    # Prints the system's name and processor type, as each test sets them.
    "uname": """
case "$1" in -m) echo "${STUB_ARCH:-aarch64}" ;; *) echo "${STUB_UNAME:-Linux}" ;; esac
""",
    # Prints the user number: 0 is the administrator.
    "id": """
echo "${STUB_UID:-0}"
""",
    # Writes down the command and runs it, as sudo would after a password. With STUB_SUDO_FAIL set
    # it refuses, as sudo does for a user who is not allowed to use it.
    "sudo": """
echo "sudo $*" >> "$STUB_LOG"
if [ -n "${STUB_SUDO_FAIL:-}" ]; then
  echo "sudo: you are not in the sudoers file." >&2
  exit 1
fi
exec "$@"
""",
    # Copies the test's download into place, or for Docker's script, writes one that "installs" Docker.
    "curl": """
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
echo "curl $url" >> "$STUB_LOG"
[ -n "${STUB_FETCH_FAIL:-}" ] && exit 22
case "$url" in
  https://get.docker.com) printf 'echo get-docker >> "$STUB_LOG"\\ncp "$STUB_BIN/docker.stub" "$STUB_BIN/docker"\\n' > "$out" ;;
  *) cp "$STUB_TARBALL" "$out" ;;
esac
""",
    # Copies the test's download into place, like the curl stand-in, for computers without curl.
    "wget": """
out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -O) out="$2"; shift 2 ;; -*) shift ;; *) url="$1"; shift ;; esac
done
echo "wget $url" >> "$STUB_LOG"
[ -n "$out" ] || exit 2
cp "$STUB_TARBALL" "$out"
""",
    # Pretends to be Docker: remembers whether QuietNet's container is "up" in a file. With
    # STUB_CONTAINER_EXISTS set, a container with no Compose labels exists, as after "docker run".
    "docker.stub": """
echo "docker $* | cloud=${QUIETNET_CLOUD-UNSET} pair=${QUIETNET_PAIR-UNSET} dir=$(pwd)" >> "$STUB_LOG"
case "$1 $2" in
  "compose version") exit "${STUB_COMPOSE_EXIT:-0}" ;;
esac
case "$1" in
  info) exit "${STUB_DAEMON_EXIT:-0}" ;;
  inspect)
    proj="${STUB_CONTAINER_PROJECT:-}"
    [ -f "$STUB_STATE/up" ] && proj=quietnet
    [ -n "$proj" ] || [ -n "${STUB_CONTAINER_EXISTS:-}" ] || exit 1
    case "$3" in
      *working_dir*) echo "${STUB_CONTAINER_DIR:-}" ;;
      *.Id*) echo "0123456789ab" ;;
      *Labels*) echo "$proj" ;;
      *Running*) echo "${STUB_RUNNING:-true}" ;;
    esac
    exit 0 ;;
  rm) rm -f "$STUB_STATE/up"; exit 0 ;;
  compose)
    case " $* " in
      *" up "*) touch "$STUB_STATE/up"; exit "${STUB_UP_EXIT:-0}" ;;
      *" down "*) rm -f "$STUB_STATE/up"; exit 0 ;;
    esac ;;
esac
exit 0
""",
    # Prints whatever the test says is listening on network ports.
    "ss": """
echo "Netid State Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process"
[ -n "${STUB_SS:-}" ] && printf '%s\\n' "$STUB_SS"
exit 0
""",
    "sysctl": """
echo "sysctl $*" >> "$STUB_LOG"
""",
    "systemctl": """
echo "systemctl $*" >> "$STUB_LOG"
""",
    "hostname": """
echo "192.168.1.50 172.17.0.1 fd00::5"
""",
    "ip": """
echo "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 1000"
""",
    "sleep": """
exit 0
""",
}

RESOLVED_LINE = ('udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=13))')
DNSMASQ_LINE = ('udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=700,fd=4))')


def fake_tarball(path, files):
    """Write a .tar.gz shaped like GitHub's download: one top folder holding `files` (name -> text)."""
    with tarfile.open(path, "w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo("QuietNet-main/" + name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))


def other_shells():
    """The extra shells on this computer the installer should also be tried with (dash, busybox ash)."""
    out = []
    if shutil.which("dash"):
        out.append([shutil.which("dash")])
    if shutil.which("busybox"):
        out.append([shutil.which("busybox"), "sh"])
    return out


class Installer(unittest.TestCase):
    """Runs install.sh against stand-in commands in a throwaway folder."""
    FILES = {"server.py": "# new\n", "Dockerfile": "FROM x\n", "docker-compose.yml": "services: {}\n",
             "LICENSE": "Proprietary\n", "static/index.html": "<html></html>\n"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="quietnet-installer-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = os.path.join(self.tmp, "bin")
        self.state = os.path.join(self.tmp, "state")
        self.sysroot = os.path.join(self.tmp, "sysroot")
        self.temp = os.path.join(self.tmp, "temp")
        for d in (self.bin, self.state, self.sysroot, self.temp, os.path.join(self.tmp, "opt")):
            os.makedirs(d)
        self.dir = os.path.join(self.tmp, "opt", "quietnet")
        self.log = os.path.join(self.tmp, "calls.log")
        open(self.log, "w").close()
        self.tarball = os.path.join(self.tmp, "download.tar.gz")
        fake_tarball(self.tarball, self.FILES)
        for tool in REAL_TOOLS:
            real = shutil.which(tool)
            if real:
                os.symlink(real, os.path.join(self.bin, tool))
        for name, body in STUBS.items():
            self.stub(name, body)
        shutil.copy(os.path.join(self.bin, "docker.stub"), os.path.join(self.bin, "docker"))

    def stub(self, name, body):
        """Write one stand-in command into the test's PATH folder."""
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body.lstrip("\n"))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def run_installer(self, *args, shell=None, script=SCRIPT, **env):
        """Run install.sh with the given options and stand-in settings; returns the finished process.

        It runs in a new session, so it has no terminal to ask questions on."""
        full = {"PATH": self.bin, "HOME": self.tmp, "TMPDIR": self.temp, "LC_ALL": "C",
                "QUIETNET_DIR": self.dir, "QUIETNET_SYSROOT": self.sysroot,
                "STUB_LOG": self.log, "STUB_STATE": self.state, "STUB_BIN": self.bin, "STUB_TARBALL": self.tarball}
        full.update(env)
        return subprocess.run((shell or ["/bin/sh"]) + [script] + list(args), env=full, cwd=self.tmp,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True, start_new_session=True, timeout=60)

    def calls(self):
        """Every stand-in command call written down so far, one per line."""
        with open(self.log) as f:
            return f.read().splitlines()

    def compose_up(self):
        """The calls that built and started QuietNet's container."""
        return [c for c in self.calls() if c.startswith("docker compose") and " up " in c]

    def assertInstalled(self, result):
        """Check the installer finished well, showing its output if it did not."""
        self.assertEqual(result.returncode, 0, result.stdout)


class Syntax(unittest.TestCase):
    def test_the_installer_is_valid_posix_shell(self):
        subprocess.run(["/bin/sh", "-n", SCRIPT], check=True)

    def test_the_installer_is_valid_for_the_other_shells_found_here(self):
        if not other_shells():
            self.skipTest("neither dash nor busybox is installed here")
        for shell in other_shells():
            subprocess.run(shell + ["-n", SCRIPT], check=True)

    def test_the_installer_can_be_run_directly(self):
        self.assertTrue(os.stat(SCRIPT).st_mode & stat.S_IXUSR)

    def test_the_only_top_level_command_is_the_call_to_main(self):
        # So a download cut off half-way defines functions and stops, doing nothing.
        with open(SCRIPT) as f:
            lines = [l.rstrip() for l in f if l.strip() and not l.startswith("#")]
        self.assertEqual(lines[-1], '{ main "$@"; exit $?; }')


class Checks(Installer):
    def test_it_refuses_to_run_on_a_mac(self):
        r = self.run_installer(STUB_UNAME="Darwin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("Start QuietNet.command", r.stdout)
        self.assertEqual([c for c in self.calls() if c.startswith("docker")], [])

    def test_it_refuses_relay_addresses_with_unsafe_characters_before_running_anything(self):
        for bad in ['https://a"b', "https://a$(id)", "https://a;reboot", "https://a b", "https://a`id`", "https://a|b"]:
            r = self.run_installer("--relay", bad, "--code", "A1B2-C3D4")
            self.assertEqual(r.returncode, 2, bad)
        self.assertEqual(self.calls(), [])

    def test_it_refuses_a_plain_http_relay_on_another_computer(self):
        r = self.run_installer("--relay", "http://evil.example", "--code", "A1B2-C3D4")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unprotected", r.stdout)
        self.assertEqual(self.calls(), [])

    def test_it_refuses_a_relay_that_only_starts_like_localhost(self):
        r = self.run_installer("--relay", "http://localhost.evil.example", "--code", "A1B2-C3D4")
        self.assertEqual(r.returncode, 2)

    def test_it_refuses_badly_formed_codes_before_running_anything(self):
        for bad in ["A1B2C3D4", "A1B2-C3D", "A1B2-C3D4E", "A1B!-C3D4", "A1B2-C3D4;id", ""]:
            r = self.run_installer("--relay", "https://relay.example", "--code", bad)
            self.assertEqual(r.returncode, 2, bad)
        self.assertEqual(self.calls(), [])

    def test_a_code_without_a_relay_is_a_mistake(self):
        r = self.run_installer("--code", "A1B2-C3D4")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--relay", r.stdout)

    def test_a_relay_without_a_code_is_a_mistake(self):
        r = self.run_installer("--relay", "https://relay.example")
        self.assertEqual(r.returncode, 2)

    def test_an_unknown_option_shows_the_usage(self):
        r = self.run_installer("--frobnicate")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--uninstall", r.stdout)

    def test_a_branch_name_with_unsafe_characters_is_refused(self):
        r = self.run_installer("--ref", "main;id")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(self.calls(), [])

    def test_it_refuses_the_top_of_the_disk_as_its_folder(self):
        r = self.run_installer(QUIETNET_DIR="/")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.calls(), [])

    def test_it_refuses_a_top_level_system_folder(self):
        r = self.run_installer(QUIETNET_DIR="/usr")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.calls(), [])

    def test_it_refuses_a_folder_that_holds_other_files(self):
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "precious.txt"), "w") as f:
            f.write("keep me")
        r = self.run_installer()
        self.assertEqual(r.returncode, 1)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "precious.txt")))
        self.assertEqual(self.compose_up(), [])

    def test_it_says_so_when_sudo_cannot_give_administrator_rights(self):
        r = self.run_installer(STUB_UID="1000", STUB_SUDO_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be obtained through sudo", r.stdout)
        self.assertNotIn("Compose plugin", r.stdout)
        self.assertEqual([c for c in self.calls() if "docker" in c], [])

    def test_uninstall_says_so_when_sudo_cannot_give_administrator_rights(self):
        r = self.run_installer("--uninstall", STUB_UID="1000", STUB_SUDO_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("could not be obtained through sudo", r.stdout)

    def test_it_refuses_a_working_copy_with_its_own_data_folder(self):
        os.makedirs(os.path.join(self.dir, "data"))
        for name in ("server.py", "docker-compose.yml", os.path.join("data", "quietnet.db")):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write("keep me")
        r = self.run_installer()
        self.assertEqual(r.returncode, 1)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "data", "quietnet.db")))
        self.assertEqual(self.compose_up(), [])

    def test_it_refuses_a_working_copy_with_git_history(self):
        os.makedirs(os.path.join(self.dir, ".git"))
        for name in ("server.py", "docker-compose.yml"):
            with open(os.path.join(self.dir, name), "w") as f:
                f.write("keep me")
        r = self.run_installer()
        self.assertEqual(r.returncode, 1)
        self.assertTrue(os.path.isdir(os.path.join(self.dir, ".git")))

    def make_unreadable_folder(self):
        """Make the install folder hold a file but be impossible to list, as a root-only folder is."""
        if os.geteuid() == 0:
            self.skipTest("the administrator can list any folder")
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "precious.txt"), "w") as f:
            f.write("keep me")
        os.chmod(self.dir, 0o311)
        self.addCleanup(os.chmod, self.dir, 0o755)

    def test_it_refuses_a_folder_it_cannot_list(self):
        self.make_unreadable_folder()
        r = self.run_installer()
        os.chmod(self.dir, 0o755)
        self.assertEqual(r.returncode, 1)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "precious.txt")))
        self.assertEqual(self.compose_up(), [])

    def test_uninstall_leaves_a_folder_it_cannot_list(self):
        self.make_unreadable_folder()
        self.run_installer("--uninstall")
        os.chmod(self.dir, 0o755)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "precious.txt")))

    def test_it_stops_when_neither_root_nor_sudo_is_available(self):
        os.remove(os.path.join(self.bin, "sudo"))
        r = self.run_installer(STUB_UID="1000")
        self.assertEqual(r.returncode, 1)
        self.assertIn("as root", r.stdout)


class Installing(Installer):
    def test_it_installs_the_files_and_starts_the_container(self):
        self.assertInstalled(self.run_installer())
        with open(os.path.join(self.dir, "server.py")) as f:
            self.assertEqual(f.read(), "# new\n")
        self.assertTrue(os.path.exists(os.path.join(self.dir, "static", "index.html")))
        up = self.compose_up()
        self.assertEqual(len(up), 1)
        self.assertTrue(up[0].startswith("docker compose -p quietnet up -d --build |"))
        self.assertTrue(up[0].endswith("/opt/quietnet"))

    def test_it_downloads_from_the_github_repository_and_branch(self):
        self.assertInstalled(self.run_installer("--ref", "v1.2"))
        self.assertIn("curl https://codeload.github.com/lpobjoy/QuietNet/tar.gz/v1.2", self.calls())

    def test_without_a_relay_no_pairing_settings_are_passed(self):
        self.assertInstalled(self.run_installer())
        self.assertIn("cloud=UNSET pair=UNSET", self.compose_up()[0])

    def test_the_relay_and_code_are_passed_to_the_container(self):
        self.assertInstalled(self.run_installer("--relay", "https://relay.example", "--code", "a1b2-c3d4"))
        self.assertIn("cloud=https://relay.example pair=A1B2-C3D4", self.compose_up()[0])

    def test_a_relay_given_without_https_has_it_added(self):
        self.assertInstalled(self.run_installer("--relay", "relay.example/", "--code", "A1B2-C3D4"))
        self.assertIn("cloud=https://relay.example pair", self.compose_up()[0])

    def test_a_relay_on_this_same_computer_may_use_http(self):
        self.assertInstalled(self.run_installer("--relay", "http://localhost:8080", "--code", "A1B2-C3D4"))
        self.assertIn("cloud=http://localhost:8080 pair", self.compose_up()[0])

    def test_the_code_is_never_written_to_a_file(self):
        self.assertInstalled(self.run_installer("--relay", "https://relay.example", "--code", "Z9Y8-X7W6"))
        for folder in (self.dir, self.sysroot, self.temp):
            for dirpath, _, names in os.walk(folder):
                for name in names:
                    with open(os.path.join(dirpath, name), "rb") as f:
                        self.assertNotIn(b"Z9Y8-X7W6", f.read(), os.path.join(dirpath, name))

    def test_the_temporary_download_folder_is_removed(self):
        self.assertInstalled(self.run_installer())
        self.assertEqual(os.listdir(self.temp), [])

    def test_it_runs_the_administrator_steps_through_sudo_when_not_root(self):
        self.assertInstalled(self.run_installer(STUB_UID="1000"))
        self.assertTrue(any(c.startswith("sudo docker compose -p quietnet up") for c in self.calls()))

    def test_it_does_not_use_sudo_when_already_root(self):
        self.assertInstalled(self.run_installer())
        self.assertEqual([c for c in self.calls() if c.startswith("sudo")], [])

    def test_it_switches_on_forwarding(self):
        self.assertInstalled(self.run_installer())
        with open(os.path.join(self.sysroot, "etc", "sysctl.d", "90-quietnet.conf")) as f:
            self.assertEqual(f.read().strip(), "net.ipv4.ip_forward=1")
        self.assertIn("sysctl --system", self.calls())

    def test_forwarding_already_set_is_left_alone(self):
        os.makedirs(os.path.join(self.sysroot, "etc", "sysctl.d"))
        with open(os.path.join(self.sysroot, "etc", "sysctl.d", "90-quietnet.conf"), "w") as f:
            f.write("net.ipv4.ip_forward=1\n")
        self.assertInstalled(self.run_installer())
        self.assertNotIn("sysctl --system", self.calls())

    def test_it_tells_the_person_to_point_the_router_at_this_computer(self):
        r = self.run_installer()
        self.assertInstalled(r)
        self.assertIn("set the DNS server to 192.168.1.50", r.stdout)
        self.assertIn("http://localhost:8377", r.stdout)
        self.assertIn("LICENSE", r.stdout)

    def test_it_says_how_to_reach_the_dashboard_from_another_computer(self):
        r = self.run_installer()
        self.assertInstalled(r)
        self.assertIn("ssh -L 8377:localhost:8377", r.stdout)
        self.assertIn("@192.168.1.50", r.stdout)

    def test_it_says_where_to_look_when_pairing(self):
        r = self.run_installer("--relay", "https://relay.example", "--code", "A1B2-C3D4")
        self.assertIn("docker logs quietnet", r.stdout)

    def test_it_stops_when_the_container_does_not_stay_running(self):
        r = self.run_installer(STUB_RUNNING="false")
        self.assertEqual(r.returncode, 1)
        self.assertIn("docker logs quietnet", r.stdout)

    def test_it_downloads_with_wget_when_curl_is_missing(self):
        os.remove(os.path.join(self.bin, "curl"))
        self.assertInstalled(self.run_installer())
        self.assertIn("wget https://codeload.github.com/lpobjoy/QuietNet/tar.gz/main", self.calls())
        with open(os.path.join(self.dir, "server.py")) as f:
            self.assertEqual(f.read(), "# new\n")

    def test_a_failed_download_stops_before_anything_is_changed(self):
        r = self.run_installer(STUB_FETCH_FAIL="1")
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(self.dir))
        self.assertEqual(self.compose_up(), [])

    def test_a_download_that_is_not_quietnet_is_refused(self):
        fake_tarball(self.tarball, {"README.md": "something else\n"})
        r = self.run_installer()
        self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(self.dir))

    def test_it_works_under_the_other_shells_found_here(self):
        if not other_shells():
            self.skipTest("neither dash nor busybox is installed here")
        for shell in other_shells():
            open(self.log, "w").close()
            self.assertInstalled(self.run_installer("--relay", "relay.example", "--code", "A1B2-C3D4", shell=shell))
            self.assertIn("cloud=https://relay.example pair=A1B2-C3D4", self.compose_up()[0])


class Updating(Installer):
    def test_running_it_again_replaces_the_files_and_leaves_nothing_stale(self):
        self.assertInstalled(self.run_installer())
        with open(os.path.join(self.dir, "old_file.py"), "w") as f:
            f.write("stale")
        fake_tarball(self.tarball, dict(self.FILES, **{"server.py": "# newer\n"}))
        self.assertInstalled(self.run_installer())
        self.assertFalse(os.path.exists(os.path.join(self.dir, "old_file.py")))
        with open(os.path.join(self.dir, "server.py")) as f:
            self.assertEqual(f.read(), "# newer\n")

    def test_updating_touches_nothing_outside_its_folder(self):
        neighbour = os.path.join(self.tmp, "opt", "other-program")
        os.makedirs(neighbour)
        self.assertInstalled(self.run_installer())
        self.assertInstalled(self.run_installer())
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, "opt"))), ["other-program", "quietnet"])

    def test_a_container_from_another_folder_is_not_fought_over(self):
        r = self.run_installer(STUB_CONTAINER_PROJECT="quietnet-main", STUB_CONTAINER_DIR="/home/pi/QuietNet-main")
        self.assertEqual(r.returncode, 1)
        self.assertIn("/home/pi/QuietNet-main", r.stdout)
        self.assertEqual(self.compose_up(), [])

    def test_a_container_with_no_compose_project_is_not_fought_over(self):
        r = self.run_installer(STUB_CONTAINER_EXISTS="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("docker rm -f quietnet", r.stdout)
        self.assertEqual(self.compose_up(), [])

    def test_the_message_about_another_container_says_it_exists_not_that_it_runs(self):
        r = self.run_installer(STUB_CONTAINER_PROJECT="quietnet-main", STUB_RUNNING="false")
        self.assertIn('a container called "quietnet" already exists', r.stdout)
        self.assertNotIn("already running", r.stdout)

    def test_a_container_started_from_a_folder_called_quietnet_is_taken_over(self):
        self.assertInstalled(self.run_installer(STUB_CONTAINER_PROJECT="quietnet"))
        self.assertEqual(len(self.compose_up()), 1)


class Docker(Installer):
    def setUp(self):
        super().setUp()
        os.remove(os.path.join(self.bin, "docker"))

    def test_without_a_terminal_or_yes_it_stops_before_installing_docker(self):
        r = self.run_installer()
        self.assertEqual(r.returncode, 1)
        self.assertIn("--yes", r.stdout)
        self.assertNotIn("curl https://get.docker.com", self.calls())

    def test_it_asks_before_installing_docker_and_respects_no(self):
        answer = os.path.join(self.tmp, "answer")
        with open(answer, "w") as f:
            f.write("n\n")
        r = self.run_installer(QUIETNET_TTY=answer)
        self.assertEqual(r.returncode, 1)
        self.assertIn("Install Docker now", r.stdout)
        self.assertNotIn("curl https://get.docker.com", self.calls())

    def test_a_yes_typed_at_the_question_installs_docker(self):
        answer = os.path.join(self.tmp, "answer")
        with open(answer, "w") as f:
            f.write("y\n")
        self.assertInstalled(self.run_installer(QUIETNET_TTY=answer))
        self.assertIn("get-docker", self.calls())

    def test_with_yes_it_installs_docker_with_dockers_own_script(self):
        self.assertInstalled(self.run_installer("--yes"))
        calls = self.calls()
        self.assertIn("curl https://get.docker.com", calls)
        self.assertIn("get-docker", calls)
        self.assertEqual(len(self.compose_up()), 1)


class DockerParts(Installer):
    def test_when_dockers_script_fails_it_points_to_dockers_own_guide(self):
        os.remove(os.path.join(self.bin, "docker"))
        self.stub("curl", """
out=""
while [ $# -gt 0 ]; do case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac; done
printf 'exit 1\\n' > "$out"
""")
        r = self.run_installer("--yes")
        self.assertEqual(r.returncode, 1)
        self.assertIn("https://docs.docker.com/engine/install/debian/", r.stdout)
        self.assertNotIn("apt-get install docker.io docker-compose", r.stdout)

    def test_the_compose_advice_does_not_offer_debians_old_compose_package(self):
        r = self.run_installer(STUB_COMPOSE_EXIT="1")
        self.assertNotIn("apt-get install docker-compose ", r.stdout)
        self.assertIn("https://docs.docker.com/engine/install/debian/", r.stdout)

    def test_it_explains_when_the_compose_command_is_missing(self):
        r = self.run_installer(STUB_COMPOSE_EXIT="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("docker compose", r.stdout)

    def test_it_says_so_when_the_docker_service_is_not_running(self):
        r = self.run_installer(STUB_DAEMON_EXIT="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("service is not running", r.stdout)
        self.assertIn("systemctl start docker", self.calls())


class Port53(Installer):
    def test_another_dns_program_on_port_53_stops_the_install(self):
        r = self.run_installer(STUB_SS=DNSMASQ_LINE)
        self.assertEqual(r.returncode, 1)
        self.assertIn("dnsmasq", r.stdout)
        self.assertEqual(self.compose_up(), [])

    def test_with_yes_systemd_resolveds_listener_is_switched_off(self):
        etc = os.path.join(self.sysroot, "etc")
        os.makedirs(etc)
        os.symlink("../run/systemd/resolve/stub-resolv.conf", os.path.join(etc, "resolv.conf"))
        self.assertInstalled(self.run_installer("--yes", STUB_SS=RESOLVED_LINE))
        with open(os.path.join(etc, "systemd", "resolved.conf.d", "quietnet.conf")) as f:
            self.assertIn("[Resolve]\nDNSStubListener=no", f.read())
        self.assertEqual(os.readlink(os.path.join(etc, "resolv.conf")), "/run/systemd/resolve/resolv.conf")
        self.assertIn("systemctl restart systemd-resolved", self.calls())

    def test_without_a_terminal_systemd_resolved_is_left_alone(self):
        r = self.run_installer(STUB_SS=RESOLVED_LINE)
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("systemctl restart systemd-resolved", self.calls())

    def test_a_running_quietnet_on_port_53_is_not_in_the_way(self):
        line = 'udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("python3",pid=900,fd=5))'
        self.assertInstalled(self.run_installer(STUB_SS=line, STUB_CONTAINER_PROJECT="quietnet"))


class Uninstalling(Installer):
    def test_uninstall_stops_the_container_and_removes_the_folder(self):
        self.assertInstalled(self.run_installer())
        r = self.run_installer("--uninstall")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(os.path.exists(self.dir))
        self.assertTrue(any(c.startswith("docker compose -p quietnet down") for c in self.calls()))

    def test_uninstall_keeps_the_data_volume_and_says_how_to_delete_it(self):
        self.assertInstalled(self.run_installer())
        r = self.run_installer("--uninstall")
        self.assertFalse(any("volume rm" in c or " -v" in c for c in self.calls()))
        self.assertIn("docker volume rm quietnet_quietnet-data", r.stdout)

    def test_uninstall_leaves_a_container_with_no_compose_project_alone(self):
        r = self.run_installer("--uninstall", STUB_CONTAINER_EXISTS="1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("left alone", r.stdout)
        self.assertFalse(any(c.startswith("docker rm") for c in self.calls()))

    def test_uninstall_leaves_a_folder_holding_other_files(self):
        os.makedirs(self.dir)
        with open(os.path.join(self.dir, "precious.txt"), "w") as f:
            f.write("keep me")
        self.run_installer("--uninstall")
        self.assertTrue(os.path.exists(os.path.join(self.dir, "precious.txt")))


class CutOff(Installer):
    def test_a_script_cut_off_half_way_does_nothing(self):
        with open(SCRIPT) as f:
            text = f.read()
        for fraction in (0.25, 0.5, 0.9):
            part = os.path.join(self.tmp, "part.sh")
            with open(part, "w") as f:
                f.write(text[:int(len(text) * fraction)])
            self.run_installer("--yes", script=part)
        cut = os.path.join(self.tmp, "cut.sh")
        with open(cut, "w") as f:
            f.write(text[:text.rindex("{ main")])
        self.run_installer("--yes", script=cut)
        self.assertEqual(self.calls(), [])
        self.assertFalse(os.path.exists(self.dir))


if __name__ == "__main__":
    unittest.main()
