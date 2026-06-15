# Test fixture for py-subprocess-shell-true (intentionally vulnerable snippets)
import subprocess


def list_dir(name):
    # ruleid: py-subprocess-shell-true
    subprocess.run("ls " + name, shell=True)


def ping(host):
    # ruleid: py-subprocess-shell-true
    subprocess.call(f"ping -c 1 {host}", shell=True)


def list_dir_safe(name):
    # ok: py-subprocess-shell-true
    subprocess.run(["ls", name])


def static_cmd():
    # ok: py-subprocess-shell-true
    subprocess.run("ls -la", shell=True)
