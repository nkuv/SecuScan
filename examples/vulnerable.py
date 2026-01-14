import subprocess

def run_cmd():
    # Vulnerable: shell=True
    subprocess.call("echo hello", shell=True)

def hardcoded():
    password = "secret_password"
