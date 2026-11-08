"""Tests for commit_state.sh (Spec 71 M1.3): a monitor run's state reaches main by rebase and retry, never by force,
and never over a pool that changed during the run. Hermetic: a local bare remote and clones, no git configuration
from the machine (no identity: the script brings its own, which a rebase on a runner needs).
Run: python3 -m unittest discover -s harvest
"""
import base64
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("commit_state.sh")
ME = ("-c", "user.name=harvest", "-c", "user.email=harvest@example.invalid")


class CommitStateTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.env = {"PATH": os.environ["PATH"], "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull, "RETRY_PAUSE": "0"}
        self.remote, self.harvest, self.runner = root / "remote.git", root / "harvest", root / "runner"
        self.git(root, "init", "--quiet", "--bare", "-b", "main", str(self.remote))
        self.git(root, "init", "--quiet", "-b", "main", str(self.harvest))
        self.git(self.harvest, "remote", "add", "origin", str(self.remote))
        self.change("pool/streams.tsv", "url\nhttp://a.example/1\n")
        self.change("README.md", "channels\n")
        self.git(root, "clone", "--quiet", "--depth", "1", self.remote.as_uri(), str(self.runner))
        self.start = self.tip()

    def tearDown(self):
        self.directory.cleanup()

    def git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True, capture_output=True,
                              text=True).stdout.strip()

    def change(self, path: str, text: str) -> None:
        """A commit pushed to main from the harvest clone (a harvest run, a README edit)."""
        (self.harvest / path).parent.mkdir(parents=True, exist_ok=True)
        (self.harvest / path).write_text(text)
        self.git(self.harvest, "add", path)
        self.git(self.harvest, *ME, "commit", "--quiet", "-m", f"change {path}")
        self.git(self.harvest, "push", "--quiet", "origin", "main")

    def tip(self) -> str:
        return self.git(self.remote, "rev-parse", "main")

    def run_state(self, state: str = "url\tstate\n", cursor: str = "0123456789abcdef\n") -> subprocess.CompletedProcess:
        (self.runner / "monitor").mkdir(exist_ok=True)
        (self.runner / "monitor" / "state.tsv").write_text(state)
        (self.runner / "monitor" / "cursor").write_text(cursor)
        return self.commit()

    def commit(self) -> subprocess.CompletedProcess:
        return subprocess.run(["sh", str(SCRIPT), str(self.runner)], env=self.env, capture_output=True, text=True)

    def shown(self, path: str) -> str:
        return self.git(self.remote, "show", f"main:{path}")

    def test_no_state_change_commits_nothing(self):
        done = self.commit()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("no change", done.stdout)
        self.assertEqual(self.run_state().returncode, 0)
        pushed = self.tip()
        done = self.commit()  # the same files again
        self.assertEqual((done.returncode, self.tip()), (0, pushed))

    def test_the_state_files_alone_are_committed_onto_main_as_the_bot(self):
        (self.runner / "stray.txt").write_text("not state\n")
        done = self.run_state()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.git(self.remote, "rev-parse", "main~1"), self.start)
        self.assertEqual(self.git(self.remote, "show", "--name-only", "--format=%an", "main").split("\n"),
                         ["github-actions[bot]", "", "monitor/cursor", "monitor/state.tsv"])

    def test_a_rejected_push_rebases_onto_a_commit_outside_the_pool(self):
        self.change("README.md", "channels, edited during the run\n")
        edited = self.tip()
        done = self.run_state()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.git(self.remote, "rev-parse", "main~1"), edited)
        self.assertEqual(self.shown("monitor/state.tsv"), "url\tstate")
        self.assertEqual(self.shown("README.md"), "channels, edited during the run")

    def test_a_pool_change_during_the_run_pushes_nothing(self):
        self.change("pool/streams.tsv", "url\n")  # a harvest push removed the row
        harvested = self.tip()
        done = self.run_state()
        self.assertEqual(done.returncode, 1)
        self.assertIn("pool or the state changed", done.stderr)
        self.assertEqual(self.tip(), harvested)

    def test_another_runs_state_on_main_pushes_nothing_even_when_it_would_merge(self):
        self.change("monitor/state.tsv", "url\tstate\n")  # a run that read the same commit and pushed first
        other = self.tip()
        done = self.run_state(state="url\tstate\n", cursor="fedcba9876543210\n")  # no textual conflict
        self.assertEqual(done.returncode, 1)
        self.assertIn("pool or the state changed", done.stderr)
        self.assertEqual(self.tip(), other)
        self.assertFalse((self.runner / ".git" / "rebase-merge").exists())

    def test_the_token_reaches_git_only_as_a_github_scoped_header_in_the_environment(self):
        shim = Path(self.directory.name) / "shim"
        shim.mkdir()
        real = subprocess.run(["sh", "-c", "command -v git"], env=self.env, capture_output=True, text=True,
                              check=True).stdout.strip()
        log = shim / "seen"
        (shim / "git").write_text(f'#!/bin/sh\nprintf "%s|%s|%s\\n" "$GIT_CONFIG_KEY_0" "$GIT_CONFIG_VALUE_0" "$*" '
                                  f'>> "{log}"\nexec "{real}" "$@"\n')
        (shim / "git").chmod(0o755)
        self.env = {**self.env, "PATH": f"{shim}:{self.env['PATH']}", "TOKEN": "s3cret-token"}
        done = self.run_state()
        self.assertEqual(done.returncode, 0, done.stderr)
        header = "AUTHORIZATION: basic " + base64.b64encode(b"x-access-token:s3cret-token").decode()
        calls = log.read_text().splitlines()
        self.assertTrue(calls)
        for call in calls:
            key, value, argv = call.split("|", 2)
            self.assertEqual((key, value), ("http.https://github.com/.extraheader", header))
            self.assertNotIn("s3cret", argv)
        for text in (done.stdout, done.stderr, (self.runner / ".git" / "config").read_text()):
            self.assertNotIn("s3cret", text)
            self.assertNotIn(header.split()[-1], text)

    def test_a_checkout_other_than_origin_main_pushes_nothing(self):
        (self.runner / "harvest.py").write_text("unreviewed\n")
        self.git(self.runner, "add", "harvest.py")
        self.git(self.runner, *ME, "commit", "--quiet", "-m", "local code")
        done = self.run_state()
        self.assertEqual(done.returncode, 1)
        self.assertIn("not origin/main", done.stderr)
        self.assertEqual(self.tip(), self.start)

    def test_it_gives_up_after_three_rejected_pushes(self):
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o755)
        done = self.run_state()
        self.assertEqual(done.returncode, 1)
        self.assertIn("failed 3 times", done.stderr)
        self.assertEqual(self.tip(), self.start)


if __name__ == "__main__":
    unittest.main()
