import subprocess
import os

def run_gobuster(url):
    wordlist="/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
    extensions = "js,txt,php"
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    
    if not os.path.exists(wordlist):
        return f"[!] Error: Wordlist not found at {wordlist}"
    
    print(f"[*] Running gobuster on {url}...")
    try:
        process = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist, "-x", extensions, "-a", user_agent, "-q"],
            capture_output=True,
            text=True,
            timeout=300)
        if process.returncode != 0:
            return f"[!] Gobuster Error: {process.stderr}"
        return process.stdout if process.stdout else "[*] No results found"
    except FileNotFoundError:
        return "[!] Error: gobuster not installed"
    except subprocess.TimeoutExpired:
        return "[!] Error: gobuster timeout (5 mins)"
    except Exception as e:
        return f"[!] Error: {str(e)}"
    