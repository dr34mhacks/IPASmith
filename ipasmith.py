#!/usr/bin/env python3
"""
IPASmith — a single-file iOS IPA dumper for Frida 17+ and modern (rootless)
jailbreaks. Forge clean, decrypted IPAs — no SSH, no scp, no iproxy, no password.

Just run it — nothing to install but the two libraries:

    pip install frida rich          # rich is optional (plain-text fallback if absent)
    python3 ipasmith.py -l          # list installed apps
    python3 ipasmith.py com.corp.app -o ~/dumps

Everything, including the Frida agent, lives in this one file.

Verified on iOS 18.3.1 (iPhone 11, arm64e) / rootless /var/jb / Frida 17.9.1.

Author:   dr34mhacks  ·  https://github.com/dr34mhacks
License:  MIT  ·  (c) 2026 dr34mhacks
Use only for security research / RE on software & devices you are allowed to test.
"""

from __future__ import annotations

import argparse
import math
import os
import plistlib
import struct
import sys
import tempfile
import time
import zipfile
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

try:
    import frida
except Exception:
    frida = None

__author__ = "dr34mhacks"
__license__ = "MIT"
__version__ = "0.1.0"
CHUNK = 4 * 1024 * 1024  # 4 MiB transfer chunks over the Frida channel


# =============================================================================
# Frida agent (runs inside the target app) — embedded so this stays one file.
# =============================================================================
AGENT_JS = r"""
'use strict';

function getExport(name){try{return Module.findGlobalExportByName(name);}catch(e){return null;}}
function nf(name,ret,args){var p=getExport(name);return p?new NativeFunction(p,ret,args):null;}

var _FILE_API=(typeof File!=='undefined');
var _open=nf('open','int',['pointer','int','int']);
var _read=nf('read','int',['int','pointer','uint']);
var _close=nf('close','int',['int']);
var _lseek=nf('lseek','int64',['int','int64','int']);

function readFileFromDisk(path){
  if(_FILE_API){
    try{var f=new File(path,'rb');f.seek(0,2);var size=f.tell();f.seek(0,0);
      var buf=f.readBytes(size);f.close();
      if(buf&&buf.byteLength===size)return buf;}catch(e){}
  }
  if(!_open||!_read||!_close||!_lseek)return null;
  try{var fd=_open(Memory.allocUtf8String(path),0,0);if(fd===-1)return null;
    var size2=_lseek(fd,0,2).toNumber();_lseek(fd,0,0);
    if(size2<=0){_close(fd);return null;}
    var mem=Memory.alloc(size2);var off=0;
    while(off<size2){var n=_read(fd,mem.add(off),size2-off);if(n<=0)break;off+=n;}
    _close(fd);return off===size2?mem.readByteArray(size2):null;
  }catch(e){return null;}
}

function machoFiletype(base){try{var magic=base.readU32();
  if(magic!==0xfeedfacf&&magic!==0xfeedface)return null;return base.add(12).readU32();}catch(e){return null;}}

function findEncryptionInfo(u){
  function rd(o){return (u[o]|(u[o+1]<<8)|(u[o+2]<<16)|(u[o+3]<<24))>>>0;}
  var magic=rd(0);var is64=(magic===0xfeedfacf);
  if(!is64&&magic!==0xfeedface)return null;
  var ncmds=rd(16);var off=is64?32:28;
  for(var i=0;i<ncmds;i++){
    if(off+20>u.length)break;
    var cmd=rd(off),cmdsize=rd(off+4);
    if(cmd===0x21||cmd===0x2C){return {cryptoff:rd(off+8),cryptsize:rd(off+12),cryptidOffset:off+16};}
    if(cmdsize===0)break;off+=cmdsize;
  }
  return null;
}

function dirname(p){var i=p.lastIndexOf('/');return i>0?p.substring(0,i):'/';}
function basename(p){return p.substring(p.lastIndexOf('/')+1);}

var _cachedBundle=null;
function getAppInfo(){
  if(_cachedBundle)return _cachedBundle;
  var mods=Process.enumerateModules();var MH_EXECUTE=0x2;var mainMod=null;
  for(var i=0;i<mods.length;i++){if(machoFiletype(mods[i].base)===MH_EXECUTE){mainMod=mods[i];break;}}
  var bundlePath=null;
  if(typeof ObjC!=='undefined'&&ObjC.available){try{bundlePath=ObjC.classes.NSBundle.mainBundle().bundlePath().toString();}catch(e){}}
  if(!bundlePath&&mainMod)bundlePath=dirname(mainMod.path);
  _cachedBundle={bundlePath:bundlePath,appDir:bundlePath?basename(bundlePath):null,
    mainExe:mainMod?basename(mainMod.path):null,mainPath:mainMod?mainMod.path:null,moduleCount:mods.length};
  return _cachedBundle;
}

var _opendir=nf('opendir','pointer',['pointer']);
var _readdir=nf('readdir','pointer',['pointer']);
var _closedir=nf('closedir','int',['pointer']);
var _readlink=nf('readlink','int',['pointer','pointer','int']);
var DT_DIR=4,DT_LNK=10;

function listDir(path){
  if(!_opendir||!_readdir||!_closedir)return null;
  var out=[];var dir=_opendir(Memory.allocUtf8String(path));if(dir.isNull())return null;
  try{var ent;while(!(ent=_readdir(dir)).isNull()){
    var type=ent.add(20).readU8();var namlen=ent.add(18).readU16();var name;
    try{name=ent.add(21).readUtf8String(namlen);}catch(e){name=ent.add(21).readCString();}
    if(!name||name==='.'||name==='..')continue;out.push({name:name,type:type});
  }}finally{_closedir(dir);}
  return out;
}

function readSymlink(path){
  if(!_readlink)return null;
  try{var buf=Memory.alloc(4096);var n=_readlink(Memory.allocUtf8String(path),buf,4095);
    if(n<=0)return null;return buf.readUtf8String(n);}catch(e){return null;}
}

function inspectFile(abs){
  var res={size:0,macho:false,encrypted:false};
  if(!_FILE_API){var d=readFileFromDisk(abs);res.size=d?d.byteLength:0;return res;}
  try{var f=new File(abs,'rb');f.seek(0,2);res.size=f.tell();f.seek(0,0);
    if(res.size>=4){var head=f.readBytes(Math.min(res.size,0x4000));var u=new Uint8Array(head);
      var magic=(u[0]|(u[1]<<8)|(u[2]<<16)|(u[3]<<24))>>>0;
      if(magic===0xfeedfacf||magic===0xfeedface){res.macho=true;var enc=findEncryptionInfo(u);
        if(enc){var cid=(u[enc.cryptidOffset]|(u[enc.cryptidOffset+1]<<8)|(u[enc.cryptidOffset+2]<<16)|(u[enc.cryptidOffset+3]<<24))>>>0;
          res.encrypted=(cid!==0);}}}
    f.close();
  }catch(e){}
  return res;
}

function walkBundle(){
  var info=getAppInfo();var root=info.bundlePath;var entries=[];if(!root)return entries;
  function walk(rel){
    var abs=rel?(root+'/'+rel):root;var items=listDir(abs);if(items===null)return;
    for(var i=0;i<items.length;i++){var it=items[i];
      var childRel=rel?(rel+'/'+it.name):it.name;var childAbs=root+'/'+childRel;
      if(it.type===DT_DIR){entries.push({rel:childRel,kind:'dir'});walk(childRel);}
      else if(it.type===DT_LNK){entries.push({rel:childRel,kind:'symlink',target:readSymlink(childAbs)});}
      else{var f2=inspectFile(childAbs);entries.push({rel:childRel,kind:'file',size:f2.size,macho:f2.macho,encrypted:f2.encrypted});}
    }
  }
  walk('');return entries;
}

function moduleForPath(abs){var m=Process.enumerateModules();for(var i=0;i<m.length;i++)if(m[i].path===abs)return m[i];return null;}
var _dlopen=nf('dlopen','pointer',['pointer','int']);
function ensureLoaded(abs){var m=moduleForPath(abs);if(m)return m;
  if(_dlopen){try{var h=_dlopen(Memory.allocUtf8String(abs),2);if(!h.isNull()){m=moduleForPath(abs);if(m)return m;}}catch(e){}}
  return null;}

function buildDecrypted(abs){
  var disk=readFileFromDisk(abs);if(!disk)return {ok:false,reason:'disk-read-failed'};
  var bytes=new Uint8Array(disk);var enc=findEncryptionInfo(bytes);
  if(!enc)return {ok:true,bytes:bytes};
  var cid=(bytes[enc.cryptidOffset]|(bytes[enc.cryptidOffset+1]<<8)|(bytes[enc.cryptidOffset+2]<<16)|(bytes[enc.cryptidOffset+3]<<24))>>>0;
  if(cid===0)return {ok:true,bytes:bytes};
  var mod=ensureLoaded(abs);if(!mod)return {ok:false,reason:'not-loaded'};
  var dec;try{dec=mod.base.add(enc.cryptoff).readByteArray(enc.cryptsize);}catch(e){return {ok:false,reason:'mem-read-failed:'+e.message};}
  if(!dec)return {ok:false,reason:'mem-read-null'};
  var db=new Uint8Array(dec);bytes.set(db.subarray(0,enc.cryptsize),enc.cryptoff);
  bytes[enc.cryptidOffset]=0;bytes[enc.cryptidOffset+1]=0;bytes[enc.cryptidOffset+2]=0;bytes[enc.cryptidOffset+3]=0;
  return {ok:true,bytes:bytes};
}

var _xfers={};
function beginFile(rel,decrypt){
  var info=getAppInfo();var abs=info.bundlePath+'/'+rel;
  try{
    if(decrypt){var r=buildDecrypted(abs);if(!r.ok)return {ok:false,reason:r.reason};
      _xfers[rel]={mode:'buf',buf:r.bytes,size:r.bytes.length};return {ok:true,size:r.bytes.length,decrypted:true};}
    var f=new File(abs,'rb');f.seek(0,2);var size=f.tell();f.seek(0,0);
    _xfers[rel]={mode:'fd',file:f,size:size};return {ok:true,size:size,decrypted:false};
  }catch(e){return {ok:false,reason:'open-failed:'+e.message};}
}
function readChunk(rel,offset,length){
  var s=_xfers[rel];if(!s)return new ArrayBuffer(0);
  var end=Math.min(offset+length,s.size);if(offset>=end)return new ArrayBuffer(0);
  if(s.mode==='buf')return s.buf.buffer.slice(s.buf.byteOffset+offset,s.buf.byteOffset+end);
  s.file.seek(offset,0);var b=s.file.readBytes(end-offset);return b||new ArrayBuffer(0);
}
function endFile(rel){var s=_xfers[rel];if(s){try{if(s.mode==='fd')s.file.close();}catch(e){}delete _xfers[rel];}return true;}

rpc.exports={
  ping:function(){return 'pong';},
  probe:function(){return getAppInfo();},
  enumerate:function(){return walkBundle();},
  beginFile:beginFile,
  readChunk:readChunk,
  endFile:endFile
};
"""


# =============================================================================
# Terminal UI  (rich if available, graceful plain-text fallback otherwise)
# =============================================================================
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        DownloadColumn, TransferSpeedColumn, TimeRemainingColumn,
    )
    from rich.prompt import IntPrompt
    from rich.align import Align
    _RICH = True
except Exception:
    _RICH = False

BANNER = r"""
 ___ ____   _    ____            _ _   _
|_ _|  _ \ / \  / ___| _ __ ___ (_) |_| |__
 | || |_) / _ \ \___ \| '_ ` _ \| | __| '_ \
 | ||  __/ ___ \ ___) | | | | | | | |_| | | |
|___|_| /_/   \_\____/|_| |_| |_|_|\__|_| |_|
"""
TAGLINE = "Forge clean, decrypted IPAs from any modern iOS jailbreak."


class UI:
    def __init__(self, no_color=False, quiet=False):
        self.quiet = quiet
        self.rich = _RICH and not no_color
        self.console = Console(highlight=False, soft_wrap=False) if self.rich else None

    def _print(self, text, style=None):
        if self.rich:
            self.console.print(text, style=style)
        else:
            print(_strip(text))

    def banner(self, version):
        if self.quiet:
            return
        if self.rich:
            lines = BANNER.strip("\n").split("\n")
            grad = ["#5ffbf1", "#37e2ff", "#4bb8ff", "#6f8cff", "#9b6bff", "#c057ff"]
            body = Text()
            body.append("\n")
            last = len(lines) - 1
            for i, ln in enumerate(lines):
                body.append("  " + ln, style=f"bold {grad[i % len(grad)]}")
                if i == last:
                    body.append(" by ", style="dim")
                    body.append("dr34mhacks", style="bold #c057ff")
                body.append("\n")
            body.append("  ⚒ ", style="bold #c057ff")
            body.append(TAGLINE, style="italic #9fb3c8")
            self.console.print(body)
            self.console.print()
        else:
            print(BANNER.rstrip("\n") + " by dr34mhacks")
            print(TAGLINE + "\n")

    def rule(self, title=""):
        if self.quiet:
            return
        if self.rich:
            self.console.rule(f"[bold cyan]{title}[/]" if title else "")
        else:
            print(f"\n== {title} ==" if title else "\n" + "-" * 60)

    def step(self, msg): self._print(rf"[cyan]\[*][/] {msg}" if self.rich else f"[*] {msg}")
    def info(self, msg): self._print(rf"[dim]\[*] {msg}[/]" if self.rich else f"[*] {msg}")
    def success(self, msg): self._print(rf"[bold green]\[+][/] {msg}" if self.rich else f"[+] {msg}")
    def warn(self, msg): self._print(rf"[bold yellow]\[!][/] {msg}" if self.rich else f"[!] {msg}")
    def error(self, msg): self._print(rf"[bold red]\[-][/] {msg}" if self.rich else f"[-] {msg}")
    def kv(self, key, value): self._print(rf"    [dim]{key:<12}[/] {value}" if self.rich else f"    {key:<12} {value}")

    @contextmanager
    def status(self, msg):
        if self.rich and not self.quiet:
            with self.console.status(f"[cyan]{msg}[/]", spinner="dots"):
                yield
        else:
            if not self.quiet:
                print(f"[*] {msg} ...")
            yield

    @contextmanager
    def download_progress(self):
        if self.rich and not self.quiet:
            prog = Progress(
                SpinnerColumn(style="cyan"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=None), DownloadColumn(), TransferSpeedColumn(),
                TimeRemainingColumn(), console=self.console, transient=False,
            )
            with prog:
                yield _RichProg(prog)
        else:
            yield _PlainProg(self.quiet)

    def app_table(self, apps):
        if self.rich:
            t = Table(title="Installed apps", title_style="bold cyan",
                      header_style="magenta", border_style="dim", expand=False)
            t.add_column("#", justify="right", style="cyan", no_wrap=True)
            t.add_column("State", no_wrap=True)
            t.add_column("Name", style="bold")
            t.add_column("Bundle ID", style="dim")
            for i, a in enumerate(apps, 1):
                t.add_row(str(i), "[green]running[/]" if a.pid else "[dim]stopped[/]", a.name, a.identifier)
            self.console.print(t)
        else:
            print(f"{'#':>3}  {'STATE':<8} {'NAME':<28} BUNDLE ID")
            for i, a in enumerate(apps, 1):
                print(f"{i:>3}  {'running' if a.pid else 'stopped':<8} {a.name[:28]:<28} {a.identifier}")

    def pick_app(self, apps):
        self.app_table(apps)
        if self.rich:
            try:
                choice = IntPrompt.ask("[cyan]Select an app to dump[/]", console=self.console,
                                       choices=[str(i) for i in range(1, len(apps) + 1)], show_choices=False)
            except (KeyboardInterrupt, EOFError):
                return None
            return apps[choice - 1]
        try:
            idx = int(input("Select an app number to dump: ").strip())
            if 1 <= idx <= len(apps):
                return apps[idx - 1]
        except (ValueError, KeyboardInterrupt, EOFError):
            return None
        return None

    def summary_panel(self, lines, title, ok=True):
        if self.rich:
            body = Text()
            for i, (k, v) in enumerate(lines):
                if i:
                    body.append("\n")
                body.append(f"{k:<13}", style="dim"); body.append(v)
            self.console.print(Panel(body, title=f"[{'green' if ok else 'red'}]{title}[/]",
                                     title_align="left", border_style="green" if ok else "red",
                                     padding=(1, 2), expand=False))
        else:
            print(f"\n=== {title} ===")
            for k, v in lines:
                print(f"  {k:<16} {v}")


class _RichProg:
    def __init__(self, prog): self.prog = prog
    def task(self, desc, total): return self.prog.add_task(desc, total=total)
    def advance(self, task, n, desc=None):
        if desc is not None:
            self.prog.update(task, description=desc, advance=n)
        else:
            self.prog.update(task, advance=n)


class _PlainProg:
    def __init__(self, quiet):
        self.quiet = quiet; self._tot = {}; self._cur = {}; self._last = {}; self._n = 0
    def task(self, desc, total):
        self._n += 1; self._tot[self._n] = max(total, 1); self._cur[self._n] = 0; self._last[self._n] = -1
        return self._n
    def advance(self, task, n, desc=None):
        if self.quiet:
            return
        self._cur[task] += n
        pct = int(100 * self._cur[task] / self._tot[task])
        if pct != self._last[task] and pct % 5 == 0:
            self._last[task] = pct
            sys.stdout.write(f"\r  transferring... {pct:3d}%"); sys.stdout.flush()
            if pct >= 100:
                sys.stdout.write("\n")


def _strip(text):
    import re
    return re.sub(r"\[/?[a-zA-Z0-9_# ]*\]", "", text)


# =============================================================================
# Core dump engine
# =============================================================================
class DumpError(Exception):
    pass


@dataclass
class Target:
    identifier: str
    name: str
    pid: int = 0


@dataclass
class DumpResult:
    app_dir: str = ""
    main_exe: str = ""
    payload_dir: "Path | None" = None
    files: int = 0
    bytes: int = 0
    decrypted: list = field(default_factory=list)
    clear_machos: list = field(default_factory=list)
    still_encrypted: list = field(default_factory=list)
    skipped: list = field(default_factory=list)


def get_device(device_id=None, host=None, timeout=10):
    if host:
        return frida.get_device_manager().add_remote_device(host)
    if device_id:
        return frida.get_device(device_id, timeout=timeout)
    return frida.get_usb_device(timeout=timeout)


def find_app(device, query):
    for a in device.enumerate_applications():
        if query in (a.identifier, a.name):
            return Target(a.identifier, a.name, a.pid or 0)
    low = query.lower()
    for a in device.enumerate_applications():
        if low in a.name.lower() or low in a.identifier.lower():
            return Target(a.identifier, a.name, a.pid or 0)
    return None


def list_apps(device):
    apps = list(device.enumerate_applications())
    apps.sort(key=lambda a: (a.pid == 0, a.name.lower()))
    return apps


class Dumper:
    def __init__(self, device, ui=None):
        self.device = device
        self.ui = ui
        self.session = None
        self.script = None
        self._spawned_pid = None

    def _on_message(self, message, data):
        if message.get("type") == "error" and self.ui:
            self.ui.warn(f"agent: {message.get('description', message)}")

    def open(self, target, mode="spawn", resume=True, spawn_wait=3.0):
        if mode == "attach":
            if not target.pid:
                raise DumpError(f"'{target.name}' is not running. Launch it and retry with --attach, "
                                f"or drop --attach to spawn it fresh.")
            self._attach(target.pid); self._load_agent(); return
        if target.pid:
            try:
                self.device.kill(target.pid); time.sleep(2.0)
            except Exception:
                pass
        try:
            pid = self.device.spawn([target.identifier])
        except Exception as e:
            raise DumpError(f"Could not spawn '{target.identifier}': {e}\n"
                            f"    Launch the app manually on the device, then retry with --attach.")
        self._spawned_pid = pid
        self._attach(pid); self._load_agent()
        if resume:
            self.device.resume(pid); self._wait_ready(spawn_wait)

    def _attach(self, pid):
        try:
            self.session = self.device.attach(pid)
        except frida.TransportError as e:
            raise DumpError(f"Attach timed out ({e}). frida-server may be wedged — on the device run "
                            f"`killall -9 frida-server` and relaunch it, then retry.")
        except Exception as e:
            raise DumpError(f"Attach failed: {e}")

    def _load_agent(self):
        self.script = self.session.create_script(AGENT_JS)
        self.script.on("message", self._on_message)
        self.script.load()
        if self.script.exports_sync.ping() != "pong":
            raise DumpError("Agent failed to initialise.")

    def _wait_ready(self, seconds):
        deadline = time.time() + seconds
        last = 0
        while time.time() < deadline:
            try:
                info = self.script.exports_sync.probe()
                if info and info.get("bundlePath"):
                    n = info.get("moduleCount", 0)
                    if n == last and n > 0:
                        return
                    last = n
            except Exception:
                pass
            time.sleep(0.4)

    def probe(self):
        info = self.script.exports_sync.probe()
        if not info or not info.get("bundlePath"):
            raise DumpError("Could not locate the app bundle (no MH_EXECUTE module found). "
                            "Make sure you targeted the app process, not a system/helper process.")
        return info

    def pull(self, out_root, result, progress=None):
        info = self.probe()
        result.app_dir = info["appDir"]
        result.main_exe = info.get("mainExe") or ""

        entries = self.script.exports_sync.enumerate()
        entries = [e for e in entries
                   if e["rel"] != "SC_Info" and not e["rel"].startswith("SC_Info/")]

        payload = out_root / "Payload"
        app_root = payload / result.app_dir
        app_root.mkdir(parents=True, exist_ok=True)
        result.payload_dir = payload

        total_bytes = sum(e.get("size", 0) for e in entries if e.get("kind") == "file")
        task = progress.task("pulling bundle", total_bytes) if progress else None

        for e in entries:
            if e["kind"] == "dir":
                (app_root / e["rel"]).mkdir(parents=True, exist_ok=True)

        for e in entries:
            rel = e["rel"]; dest = app_root / rel; kind = e["kind"]
            if kind == "dir":
                continue
            if kind == "symlink":
                self._make_symlink(dest, e.get("target")); continue

            dest.parent.mkdir(parents=True, exist_ok=True)
            decrypt = bool(e.get("macho") and e.get("encrypted"))
            if e.get("macho") and not decrypt:
                result.clear_machos.append(rel)
            r = self.script.exports_sync.begin_file(rel, decrypt)

            if not r.get("ok") and decrypt:
                self.ui and self.ui.warn(f"could not decrypt {rel} ({r.get('reason')}); copying as-is")
                result.still_encrypted.append(rel)
                r = self.script.exports_sync.begin_file(rel, False)
            if not r.get("ok"):
                self.ui and self.ui.warn(f"skipped {rel} ({r.get('reason')})")
                result.skipped.append(rel); continue

            size = r.get("size", 0)
            self._stream_to(dest, rel, size, progress, task)
            self.script.exports_sync.end_file(rel)
            result.files += 1
            result.bytes += size
            if r.get("decrypted"):
                result.decrypted.append(rel)
                os.chmod(dest, 0o755)

        if result.main_exe:
            mp = app_root / result.main_exe
            if mp.exists():
                os.chmod(mp, 0o755)
        return result

    def _stream_to(self, dest, rel, size, progress, task):
        off = 0
        with open(dest, "wb") as f:
            while off < size:
                chunk = self.script.exports_sync.read_chunk(rel, off, CHUNK)
                if not chunk:
                    break
                if not isinstance(chunk, (bytes, bytearray)):
                    chunk = bytes(chunk)
                f.write(chunk); off += len(chunk)
                if progress and task is not None:
                    progress.advance(task, len(chunk), desc=f"pulling [dim]{_short(rel)}[/]")

    @staticmethod
    def _make_symlink(dest, target):
        if not target:
            return
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            os.symlink(target, dest)
        except OSError:
            pass

    def close(self, kill_spawned=True):
        try:
            if self.script:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass
        if kill_spawned and self._spawned_pid:
            try:
                self.device.kill(self._spawned_pid)
            except Exception:
                pass


def _short(rel, n=40):
    return rel if len(rel) <= n else "…" + rel[-(n - 1):]


# =============================================================================
# Packaging + verification  (plain zip, NO ad-hoc re-sign — let the device sign)
# =============================================================================
def make_ipa(out_root, ipa_path):
    payload = out_root / "Payload"
    if not payload.is_dir():
        raise FileNotFoundError(f"no Payload/ directory in {out_root}")
    if ipa_path.exists():
        ipa_path.unlink()
    with zipfile.ZipFile(ipa_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(payload):
            dirs.sort()
            root_p = Path(root)
            for name in sorted(files):
                full = root_p / name
                rel = full.relative_to(out_root).as_posix()
                if full.is_symlink():
                    zi = zipfile.ZipInfo(rel); zi.create_system = 3
                    zi.external_attr = 0xA1FF << 16
                    zf.writestr(zi, os.readlink(full))
                else:
                    st = full.lstat()
                    zi = zipfile.ZipInfo(rel); zi.create_system = 3
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = (st.st_mode & 0xFFFF) << 16
                    with open(full, "rb") as fh:
                        zf.writestr(zi, fh.read())
    return ipa_path


def _entropy(b):
    if not b:
        return 0.0
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _crypt_region(path):
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if data[:4] not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return None
    ncmds = struct.unpack("<I", data[16:20])[0]; off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, sz = struct.unpack("<II", data[off:off + 8])
        if cmd in (0x21, 0x2C):
            co, cs, cid = struct.unpack("<III", data[off + 8:off + 20])
            return cid, _entropy(data[co:co + cs]), data[co:co + 8].hex()
        if sz == 0:
            break
        off += sz
    return None


def verify(app_root):
    report = {"main": None, "machos": [], "encrypted_left": [], "ok": True}
    main_name = None
    info_plist = app_root / "Info.plist"
    if info_plist.exists():
        try:
            with open(info_plist, "rb") as f:
                pl = plistlib.load(f)
            main_name = pl.get("CFBundleExecutable")
            report["bundle_id"] = pl.get("CFBundleIdentifier")
            report["version"] = pl.get("CFBundleShortVersionString")
        except Exception:
            pass
    for root, _, files in os.walk(app_root):
        for name in files:
            p = Path(root) / name
            if p.is_symlink():
                continue
            r = _crypt_region(p)
            if r is None:
                continue
            cid, ent, first8 = r
            rel = p.relative_to(app_root).as_posix()
            entry = {"file": rel, "cryptid": cid, "entropy": round(ent, 2)}
            report["machos"].append(entry)
            if cid != 0:
                report["encrypted_left"].append(rel); report["ok"] = False
            if main_name and name == main_name:
                report["main"] = entry
    return report


# =============================================================================
# CLI
# =============================================================================
EPILOG = """\
examples:
  python3 ipasmith.py                      interactive: pick a running app
  python3 ipasmith.py -l                   list installed apps
  python3 ipasmith.py com.corp.app         dump by bundle id (spawns a fresh instance)
  python3 ipasmith.py "My App" -o ~/dumps  dump by display name into a folder
  python3 ipasmith.py com.corp.app --attach   attach to the running app instead
  python3 ipasmith.py com.corp.app --device ID
  python3 ipasmith.py com.corp.app --host IP:PORT

IPASmith pulls everything over the Frida channel — no SSH, no scp, no iproxy,
no password, and nothing left behind on the device.
"""


def build_parser():
    p = argparse.ArgumentParser(
        prog="ipasmith.py",
        description="Forge clean, decrypted IPAs from any modern iOS jailbreak.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?", help="bundle id or app name (omit for interactive picker)")
    p.add_argument("-l", "--list", action="store_true", help="list installed applications and exit")
    p.add_argument("-o", "--output", help="output directory (default: current directory)")
    p.add_argument("--device", help="frida device id (see: frida-ls-devices)")
    p.add_argument("--host", help="connect to a networked frida-server, host[:port]")
    p.add_argument("--attach", action="store_true",
                   help="attach to the running app instead of spawning a fresh instance")
    p.add_argument("--no-resume", action="store_true", help="spawn but leave the app suspended (advanced)")
    p.add_argument("--spawn-wait", type=float, default=3.0, help="seconds to let a spawned app settle (default 3)")
    p.add_argument("--keep-dir", action="store_true", help="keep the unpacked Payload/ next to the .ipa")
    p.add_argument("--no-color", action="store_true", help="disable colours / animations")
    p.add_argument("-q", "--quiet", action="store_true", help="minimal output")
    p.add_argument("-V", "--version", action="version", version=f"IPASmith {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    ui = UI(no_color=args.no_color, quiet=args.quiet)

    if frida is None:
        ui.error("frida is not installed. Try:  pip install 'frida>=17' rich")
        return 2

    ui.banner(__version__)

    try:
        with ui.status("connecting to device"):
            device = get_device(device_id=args.device, host=args.host)
    except Exception as e:
        ui.error(f"no device: {e}")
        ui.info("Check: device plugged in and frida-server running (frida-ps -U).")
        return 2
    ui.success(f"device: [bold]{getattr(device, 'name', 'unknown')}[/]")
    for k, v in _device_details(device):
        ui.kv(k, v)

    if args.list:
        try:
            with ui.status("enumerating applications"):
                apps = list_apps(device)
        except Exception as e:
            ui.error(f"could not list apps: {e}"); return 2
        ui.app_table(apps); return 0

    target = None
    if args.target:
        with ui.status("locating app"):
            target = find_app(device, args.target)
        if not target:
            ui.error(f"app not found: {args.target}")
            ui.info("Run with -l to see installed bundle ids."); return 2
    else:
        try:
            with ui.status("enumerating applications"):
                apps = list_apps(device)
        except Exception as e:
            ui.error(f"could not list apps: {e}"); return 2
        if not apps:
            ui.error("no applications found on device."); return 2
        chosen = ui.pick_app(apps)
        if not chosen:
            ui.warn("nothing selected."); return 1
        target = Target(chosen.identifier, chosen.name, chosen.pid or 0)

    ui.rule("forge")
    ui.kv("app", target.name)
    ui.kv("bundle id", target.identifier)
    ui.kv("mode", "attach (running)" if args.attach
          else ("spawn fresh (kill running)" if target.pid else "spawn fresh"))

    out_base = Path(args.output).expanduser() if args.output else Path.cwd()
    out_base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="ipasmith_"))

    dumper = Dumper(device, ui=ui)
    result = DumpResult()
    rc = 0
    try:
        with ui.status("attaching / spawning"):
            dumper.open(target, mode="attach" if args.attach else "spawn",
                        resume=not args.no_resume, spawn_wait=args.spawn_wait)
        info = dumper.probe()
        ui.success(f"bundle: [bold]{info['appDir']}[/]  (main: {info.get('mainExe')})")
        ui.info(f"path: [dim]{info['bundlePath']}[/]")

        with ui.download_progress() as prog:
            dumper.pull(work, result, progress=prog)

        total_machos = len(result.decrypted) + len(result.clear_machos) + len(result.still_encrypted)
        ui.success(f"pulled {result.files} files ({_human(result.bytes)})")
        ui.success(f"Mach-Os: {total_machos} total — "
                   f"{len(result.decrypted)} decrypted, {len(result.clear_machos)} already unencrypted")
        if result.still_encrypted:
            ui.warn(f"{len(result.still_encrypted)} binaries could not be decrypted (copied as-is)")

        safe = _safe_name(info["appDir"].removesuffix(".app") or target.name)
        ipa_path = out_base / f"{safe}.ipa"
        with ui.status("packaging IPA"):
            make_ipa(work, ipa_path)

        with ui.status("verifying decryption"):
            report = verify(work / "Payload" / result.app_dir)

        _print_summary(ui, ipa_path, result, report)
        if not report["ok"]:
            rc = 3

        if args.keep_dir:
            dest = out_base / f"{safe}_Payload"
            if dest.exists():
                import shutil as _sh; _sh.rmtree(dest)
            (work / "Payload").rename(dest)
            ui.info(f"unpacked bundle: [dim]{dest}[/]")

    except DumpError as e:
        ui.error(str(e)); rc = 2
    except KeyboardInterrupt:
        ui.warn("interrupted."); rc = 130
    except Exception as e:
        ui.error(f"unexpected error: {e}"); rc = 1
    finally:
        dumper.close()
        import shutil as _sh
        if not args.keep_dir:
            _sh.rmtree(work, ignore_errors=True)
    return rc


def _print_summary(ui, ipa_path, result, report):
    ok = report["ok"]
    size = _human(ipa_path.stat().st_size) if ipa_path.exists() else "n/a"
    # Headline status as a clean [+]/[!] line — not inside the box.
    if ok:
        ui.success(f"forged [bold]{ipa_path.name}[/]  ·  {size}  ·  {result.files} files")
    else:
        ui.warn(f"forged [bold]{ipa_path.name}[/] with warnings  ·  {size}")

    main = report.get("main") or {}
    total_machos = len(result.decrypted) + len(result.clear_machos) + len(result.still_encrypted)
    lines = [
        ("output", str(ipa_path)),
        ("Mach-Os", f"{total_machos} · {len(result.decrypted)} decrypted · "
                    f"{len(result.clear_machos)} already clear"),
    ]
    if report.get("bundle_id"):
        lines.append(("bundle id", report["bundle_id"]))
    if report.get("version"):
        lines.append(("version", report["version"]))
    if main:
        verdict = "decrypted" if main["cryptid"] == 0 else "STILL ENCRYPTED"
        lines.append(("main binary", f"cryptid={main['cryptid']} · entropy={main['entropy']} → {verdict}"))
    if report["encrypted_left"]:
        lines.append(("encrypted", ", ".join(report["encrypted_left"][:4]) +
                      (" …" if len(report["encrypted_left"]) > 4 else "")))
    ui.summary_panel(lines, "summary", ok=ok)


def _device_details(device):
    """Best-effort device facts to print under the device name."""
    rows = []
    did = getattr(device, "id", None)
    if did and did not in ("local", "socket"):
        rows.append(("id", str(did)))
    try:
        p = device.query_system_parameters() or {}
    except Exception:
        p = {}
    osd = p.get("os", {}) if isinstance(p, dict) else {}
    ver = " ".join(str(x) for x in (osd.get("name"), osd.get("version")) if x).strip()
    build = osd.get("build")
    if ver:
        rows.append(("os", ver + (f" ({build})" if build else "")))
    plat = " · ".join(str(x) for x in (p.get("platform"), p.get("arch")) if x)
    if plat:
        rows.append(("platform", plat))
    if p.get("name") and p.get("name") != getattr(device, "name", None):
        rows.append(("host", str(p["name"])))
    if p.get("access"):
        rows.append(("access", str(p["access"])))
    try:
        rows.append(("frida", frida.__version__))
    except Exception:
        pass
    return rows


def _human(n):
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.1f} {unit}" if unit != "B" else f"{int(f)} B"
        f /= 1024
    return f"{f:.1f} GB"


def _safe_name(name):
    keep = "-_.() "
    cleaned = "".join(c for c in name if c.isalnum() or c in keep).strip()
    return cleaned.replace(" ", "_") or "app"


if __name__ == "__main__":
    sys.exit(main())
