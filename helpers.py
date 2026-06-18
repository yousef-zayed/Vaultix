import hashlib
import pyperclip
import time
import subprocess
import sys
import os
import requests
import threading
from zxcvbn import zxcvbn


## shell script triggering the windows hello UI
def windows_hello_auth() -> bool:
    result = subprocess.run([
        "powershell",
        "-Command",
        """
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        
        $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        
        Function Await($WinRtTask, $ResultType) {
            $asTaskSpecific = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTaskSpecific.Invoke($null, @($WinRtTask))
            $netTask.Wait()
            $netTask.Result
        }

        $op = [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime]::RequestVerificationAsync('Authenticate to access your vault')
        $result = Await $op ([Windows.Security.Credentials.UI.UserConsentVerificationResult,Windows.Security.Credentials.UI,ContentType=WindowsRuntime])
        
        if ($result -eq 'Verified') { exit 0 } else { exit 1 }
        """,
    ], creationflags=subprocess.CREATE_NEW_CONSOLE)

    return result.returncode == 0


def authenticate() -> bool:
    '''
    platform adapter for user authentication
    :return: True if the user is authenticated successfully, False otherwise
    :rtype: bool
    :raise NotImplementedError: if the platform is not supported
    '''
    ## platform adapter for user authentication
    if sys.platform == "win32":
        return windows_hello_auth()
    elif sys.platform.startswith("linux"):
        import pam, getpass, pwd
        os_user = pwd.getpwuid(os.getuid()).pw_name
        p = pam.pam()
        password = getpass.getpass("System password: ")
        return p.authenticate(os_user, password)
    else:
        raise NotImplementedError("Unsupported platform for authentication")

def clear_screen():
    ## clear the terminal screen
    os.system('cls' if sys.platform == 'win32' else 'clear')


def copy_to_clipboard(pswd: str):
    pyperclip.copy(pswd)
    clear_clipboard(300)


def clear_clipboard(seconds: int):
    def _clear():
        time.sleep(seconds)
        pyperclip.copy('')

    thread = threading.Thread(target=_clear, daemon=True)
    thread.start()


def confirmation(msg : str) -> bool:
    ## operation checker
    ans = input(f"{msg}? (y/n) ").strip().lower()
    while ans not in ['y', 'yes', 'n', 'no']:
        ans = input(f"{msg}? (y/n) ").strip().lower()

    return ans in ['y', 'yes']


def check_strength(pswd:str) -> list:
    '''
    checks the strength of a given password based on a score, crack time, and how many times was it compromised

    :param pswd: the password that's going to be checked
    :type pswd: str
    :raise ConnectionError: if the user doesn't have internet
    :return: the score, a warning if any, suggestions, crack time, and how many times was it compromised
    :rtype: list
    '''
    result = zxcvbn(pswd)

    score = result["score"]
    warning = result["feedback"]["warning"]
    suggestions = result["feedback"]["suggestions"]
    crack_time = result["crack_times_display"]["offline_fast_hashing_1e10_per_second"]

    sha1 = hashlib.sha1(pswd.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    count = 0
    try:
        pwned = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        pwned_list = pwned.text.splitlines()
        for line in pwned_list:
            h, c = line.split(":")
            if h == suffix:
                count = int(c)
                break
    except ConnectionError:
        raise ConnectionError

    return {
        "score": f"{score * 25}%",
        "warning": warning,
        "suggestions": suggestions,
        "crack_time": crack_time,
        "number of breaches containing this password": count
    }


_timer = None

def update_activity(callback):
    global _timer
    if _timer is not None:
        _timer.cancel()
    _timer = threading.Timer(300, callback)
    _timer.daemon = True
    _timer.start()
