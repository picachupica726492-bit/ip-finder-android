# IP Finder (Android)

Finds a website's IP addresses using in-app versions of 15 recon tools:
ping, nslookup, dig, host, whois, dnsrecon, dnsenum, fierce, theHarvester,
amass, subfinder, assetfinder, httpx, whatweb, nmap.

Android apps cannot run desktop command-line tools without root, so each tool
is re-implemented in pure Python (see the header of `core.py`). Results come
from the same kinds of sources: DNS, WHOIS, certificate-transparency logs,
passive DNS, HTTP fingerprinting and a TCP port check.

Use only on domains you own or have written permission to test.

## Get the APK (no programming setup needed) - GitHub Actions

1. Create a free account at https://github.com and a new repository.
2. Upload every file in this folder, including the hidden `.github` folder
   (easiest: install Git, then `git add . && git commit && git push`).
3. Open the repository's **Actions** tab -> **Build Android APK** -> **Run workflow**
   (it also starts automatically on every push to `main`).
4. Wait for the build to finish (the first build takes roughly 20-40 minutes).
5. Open the finished run, scroll to **Artifacts**, download `ip-finder-apk`,
   and unzip it to get the `.apk` file.

## Install on your phone

1. Copy the `.apk` to your phone.
2. Open it. If asked, allow "Install unknown apps" for your file manager/browser.
3. Tap Install, then open **IP Finder** from your app drawer.

## Build locally instead (Linux / WSL)

    sudo apt install -y git zip unzip openjdk-17-jdk autoconf automake libtool \
        pkg-config zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo6 cmake \
        libffi-dev libssl-dev
    pip install buildozer cython==0.29.36
    buildozer -v android debug      # APK appears in ./bin/

## Try it on a desktop first

    pip install kivy certifi
    python3 main.py

## Notes

- The APK is a debug build, which is fine for personal use. Publishing on the
  Play Store needs a signed release (`buildozer android release`) and a
  developer account.
- Some sources (HackerTarget, CertSpotter) are rate-limited; the Tools tab shows
  when one refuses. Port scanning (nmap) uses a small set of common ports.
- If several IPs appear, or a CDN note is shown, the IPs may belong to a CDN
  such as Cloudflare rather than the origin server.
