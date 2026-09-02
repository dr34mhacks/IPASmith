<div align="center">

```
██╗██████╗  █████╗ ███████╗███╗   ███╗██╗████████╗██╗  ██╗
██║██╔══██╗██╔══██╗██╔════╝████╗ ████║██║╚══██╔══╝██║  ██║
██║██████╔╝███████║███████╗██╔████╔██║██║   ██║   ███████║
██║██╔═══╝ ██╔══██║╚════██║██║╚██╔╝██║██║   ██║   ██╔══██║
██║██║     ██║  ██║███████║██║ ╚═╝ ██║██║   ██║   ██║  ██║
╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
                                                                                                                                                                                            
```

### 🔨 Forge clean, decrypted IPAs from any modern iOS jailbreak.

*A modern, Frida-native successor to `frida-ios-dump` - built for Frida 17+, rootless jailbreaks, and the latest iOS.*

![python](https://img.shields.io/badge/python-3.8%2B-blue)
![frida](https://img.shields.io/badge/frida-17%2B-orange)
![ios](https://img.shields.io/badge/iOS-15%20→%2018.3.1-black)
![license](https://img.shields.io/badge/license-MIT-green)
![ssh](https://img.shields.io/badge/SSH-not%20required-brightgreen)

** Made with <3 by [dr34mhacks](https://github.com/dr34mhacks)**

</div>

---

## Why another dumper?

The classic tools break on today's stack, and they break *quietly*:

- **Frida 17 removed the built-in `ObjC` bridge.** Scripts that call `ObjC.classes.NSBundle…` to find the app silently fall through to fragile guesswork. On a **rootless** jailbreak (`/var/jb`) that guesswork happily "finds" `systemhook.dylib` instead of your app and dumps *nothing* — then hangs trying to SCP the jailbreak's own files.
- **They lean on SSH/SCP.** That means `iproxy`, an SSH server, the right root password, and a second transport layered on top of the Frida channel you *already have* - the single biggest source of "it just hangs."
- **They can't spawn.** If the app isn't already foregrounded, you're stuck. And attaching to an app iOS suspended in the background frequently times out.

**IPASmith** is a ground-up rebuild that fixes all of it:

> It finds your app by reading Mach-O headers (not by guessing paths), decrypts in memory, and streams the whole bundle back **over the Frida channel** ; no SSH, no `iproxy`, no password, nothing left on the device.

---


## 🛠️ How the forge works

```
┌────────────────────┐                    ┌────────────────────────────┐
│     IPASmith       │   spawn/attach     │   target app (on device)   │
│  (Mac/Linux/Win)   │ ─────────────────▶ │    ── Frida agent ──       │
│                    │                    │                            │
│                    │ ◀───────────────── │  scan Mach-O headers       │
└────────────────────┘   Frida channel    └────────────────────────────┘
         │           (decrypted bytes)                 │
         │              no SSH!                        │
         ▼                                             ▼
   ┌───────────┐                              ┌──────────────────┐
   │  App.ipa  │                              │  cryptid = 0     │
   │  (ready)  │                              │  verified clean  │
   └───────────┘                              └──────────────────┘
```

No SSH. No `iproxy`. No root password. Everything streams over the Frida channel you already have.

---

## 🚀 Usage

```bash
# Pick an app from an interactive menu:
python3 ipasmith.py

# List everything installed:
python3 ipasmith.py -l

# Dump by bundle id (spawns a fresh instance automatically):
python3 ipasmith.py com.corp.app

# ...or by display name, into a folder of your choice:
python3 ipasmith.py "My App" -o ~/dumps

# Attach to the already-running app instead of spawning:
python3 ipasmith.py com.corp.app --attach

# Target a specific device / a networked frida-server:
python3 ipasmith.py com.corp.app --device 00008030-000A69C0…
python3 ipasmith.py com.corp.app --host 192.168.1.20:27042
```

<img width="1624" height="984" alt="image" src="https://github.com/user-attachments/assets/3cfe79d8-b9c6-497b-8866-39483ce12f07" />


### What a dump looks like

```
[+] device: iPhone
    id           00008030-XXXXXXXXXXXXXXXX
    os           iPhone OS 18.3.1
    platform     darwin · arm64
    frida        17.9.1
──────────────────────────────── forge ────────────────────────────────
    app          My App
    bundle id    com.corp.app
    mode         spawn fresh
[+] bundle: App.app  (main: App)
[*] pulling bundle  ━━━━━━━━━━━━━━━━━━  36.4/36.4 MB  12.1 MB/s
[+] pulled 214 files (36.4 MB)
[+] Mach-Os: 18 total — 1 decrypted, 17 already unencrypted
[+] forged App.ipa  ·  14.1 MB  ·  214 files
╭─ summary ─────────────────────────────────────────────╮
│  output       ~/dumps/App.ipa                          │
│  Mach-Os      18 · 1 decrypted · 17 already clear      │
│  bundle id    com.corp.app                             │
│  version      2.9.0                                    │
│  main binary  cryptid=0 · entropy=6.09 → decrypted     │
╰────────────────────────────────────────────────────────╯
```

---

## 📱 Compatibility - built for the *latest* iOS

IPASmith is deliberately **jailbreak- and version-agnostic**: it never hardcodes a jailbreak path or relies on an OS-version quirk. If frida-server runs, IPASmith dumps.

| Environment | Status |
|---|---|
| **iOS 18.3.1** (build 22D72), iPhone 11 / arm64e | ✅ **verified** |
| Rootless jailbreaks - **Dopamine** & friends (`/var/jb`) | ✅ verified |
| Rootful jailbreaks - palera1n, unc0ver, Taurine | ✅ supported |
| Frida **17.x** (no ObjC bridge) | ✅ first-class |
| Frida 16.x and older | ✅ supported (uses ObjC when present) |
| iOS 15 / 16 chained-fixups (arm64e PAC) | ✅ preserved via disk-image splice |

> **Rootless, done right.** On `/var/jb` setups the old path-guessing heuristics mistake the jailbreak's injected `systemhook.dylib` for your app. IPASmith's `MH_EXECUTE` detection simply doesn't care where the jailbreak lives.

---

## 🆚 IPASmith vs `frida-ios-dump`

| | `frida-ios-dump` (classic) | **IPASmith** |
|---|---|---|
| App detection | ObjC `NSBundle` → path guessing | Mach-O `MH_EXECUTE` scan |
| Frida 17 (no ObjC bridge) | ⚠️ silently misbehaves | ✅ native |
| Rootless (`/var/jb`) | ⚠️ picks the wrong module | ✅ correct |
| File transfer | SSH / SCP (`iproxy`, password) | ✅ Frida channel only |
| Not-yet-loaded frameworks | often missed | ✅ `dlopen()`-ed & decrypted |
| App must be running | usually yes | ✅ spawns fresh |
| On-device temp files | left in `/tmp` | ✅ none written |
| Reporting | "N/N" (re-counts clear binaries) | ✅ honest decrypted vs clear |

---

## ❓ FAQ

**It says "1 decrypted, 17 already unencrypted" - did it miss the frameworks?**
> No - that's the honest count. The App Store frequently encrypts only the **main executable**; many third-party frameworks ship with `cryptid = 0`. IPASmith decrypts what's actually encrypted and copies the rest verbatim. Every binary in the output is verified `cryptid = 0`.

**Do I need SSH / a root password?**
> No. Everything moves over the Frida channel. (SSH isn't used at all.)

**Attach keeps timing out.**
> That's iOS suspending the backgrounded app. IPASmith spawns a fresh instance by default to sidestep it; if you specifically need the running process, foreground it and use `--attach`. If *all* attaches hang, frida-server is wedged — `killall -9 frida-server` on the device (launchd respawns it).

**Some `SC_Info/*` files were skipped.**
> Intentional. That's the FairPlay ticket - DRM metadata that's unreadable and unwanted in a decrypted IPA.

**The dumped IPA won't launch when I sideload it.**
> Don't ad-hoc re-sign a dump and expect it to run - a foreign signature fights the device's own signing. Install the plain IPA on a jailbroken device / Corellium and let *it* sign on install, or sign with **your own** developer cert + provisioning profile or Trollstore for the win.

---

## 🧯 Troubleshooting

| Symptom | Fix |
|---|---|
| `no device` | Plug in over USB; confirm frida-server is running (`frida-ps -U`). |
| `Attach timed out` | Drop `--attach` (spawn fresh), or `killall -9 frida-server` on device. |
| `Could not spawn …` | Launch the app manually, then `--attach`. |
| `app not found` | `ipasmith -l` to get the exact bundle id. |
| Frida version mismatch | Make desktop Frida match the device's frida-server. |

---

## ⚖️ Legal & ethics

IPASmith is for **security research, reverse engineering, and interoperability on software and devices you own or are explicitly authorized to test**. Decrypting App Store binaries may be restricted by the App Store terms and by law in your jurisdiction. Don't redistribute decrypted apps or use IPASmith for piracy. You are responsible for how you use it.

---

## 🙌 Credits

- Built by **[dr34mhacks](https://github.com/dr34mhacks)**.
- Standing on the shoulders of **AloneMonkey's `frida-ios-dump`** and the wider Frida community.
