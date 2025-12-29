#!/usr/bin/env python3
"""Pass2KeePass - a pass to keepass translator, by Dalker

Goal: Translate a file structure from pass (https://www.passwordstore.org) into
      a portable KeePass file, for use with smartphone clients (that typically allow
      authentication by fingerprint after a *strong* password was input once)

Reason: When looking for a pass-to-keepass exporter, the following was found:
        https://github.com/wichmannpas/pass_to_keepass
        However, it uses a keepassdb that is not available in a working version
        at the time of writing (pip install leads to error and no AUR version
        exists). After trying shortly to adapt a fork of the aforementioned script,
        to the available pykeepass module, it was deemed more reasonable to restart
        from scratch, while keeping the python language and some inspiration from
        the original pass_to_keepass.
        The only portion of code that remains is the one-liner used to read a single
        password from the password store, so that single line retains the copyright
        2016 Pascal Wichmann under Apache License (follow link above), whereas the
        rest of the script is copyright 2022 Daniel Kessler under GPLv2.

Versions: v1.0 (2022-06.18) - first working version, does the basics

TODO: - make async actually do something useful or get rid of it so that progress can
        be shown again in a synchronous way
      - add command-line arguments for export file, subdir(s) and keyfile
      - let user insert master password for exported keepass within password store itself,
        as well as possibly default args for export file, subdir(s) and keyfile
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import time
import sys
from getpass import getpass
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from pykeepass import pykeepass


@dataclass
class PassEntry:
    """A password entry, ready for keepass."""

    group: PassGroup
    title: str
    username: Optional[str] = None
    password: Optional[str] = None
    url: str = None
    notes: str = None


@dataclass
class PassGroup:
    """A password group, containing groups or entries."""

    name: str
    parent_group: Optional[PassGroup] = None
    entries: list = field(default_factory=lambda: [])
    subgroups: list = field(default_factory=lambda: [])

    def new_group(self, name: str) -> PassGroup:
        """Create a new subgroup in this group."""
        group = PassGroup(parent_group=self, name=name)
        self.subgroups.append(group)
        return group

    def new_entry(self, title: str) -> PassEntry:
        """Create a new entry in this group."""
        entry = PassEntry(group=self, title=title)
        self.entries.append(entry)
        return entry


class Pass:
    """An interface for the linux `pass` utility."""

    BASE_PATH = "~/.password-store/"

    def __init__(self, store_path=BASE_PATH):
        """Initialize attributes."""
        self._base_path = Path(store_path).expanduser()
        self._base_index = len(Path(self.BASE_PATH).expanduser().as_posix()) + 1
        self._base_group = PassGroup(name=self._base_path.name)
        asyncio.run(self._read_store(self._base_path, self._base_group))

    async def _read_entry(self, path: Path, group: PassGroup, entry: PassEntry):
        """Read a Password Store entry.

        NB: from Password Group's point of view, this is a group, but we want
            it to become an entry, with its parent as the actual group
        """
        pass_path = path.as_posix()[self._base_index:-4]
        pwd = await self._get_password_from_pass(pass_path)
        title = path.name[:-4]
        match title:
            case "user" | "login":
                entry.username = pwd
            case "pass":
                entry.password = pwd
            case "url" | "server":
                entry.url = pwd
            case _:
                # print("-> unknown type:", subpath.name)
                extra_entry = group.new_entry(title=title)
                extra_entry.password = pwd

    async def _read_store(self, path: Path, group: PassGroup):
        """Recursively read all passwords in password store."""
        # print("processing", group.name)
        gathers = []
        entries = [sp for sp in path.iterdir()
                   if sp.is_file() and sp.name.endswith(".gpg")]
        if entries:
            entry = group.parent_group.new_entry(path.name)
            gathers.append(asyncio.gather(*[self._read_entry(subpath, group, entry)
                                          for subpath in entries]))
        g = asyncio.gather(*[self._add_group(subpath, group) for subpath in
                           [sp for sp in path.iterdir() if sp.is_dir()]])
        await asyncio.gather(*gathers, g)

    async def _add_group(self, path: Path, parent: PassGroup):
        """Add a group."""
        await self._read_store(path, parent.new_group(path.name))

    async def _get_password_from_pass(self, pass_path: str) -> str:
        """Get the pasword from pass."""
        # following line is copyright 2016 Pascal Wichmann under Apache License
        return subprocess.check_output(['pass', pass_path]).decode().splitlines()[0]

    def print(self, group=None):
        """Show contents."""
        if group is None:
            group = self._base_group
        print(group.name, f"(parent: {group.parent_group.name})"
              if group.parent_group else "")
        for entry in group.entries:
            if entry is not None:
                print("-> ", entry.title,
                      f"({entry.username})" if entry.username else "",
                      ": ******" if entry.password else ": NO PASS!!",
                      )
        for subgroup in group.subgroups:
            self.print(subgroup)

    def export(self, fname: str, pwd: str, kfile: str = None):
        """Export to a new KeePass file."""
        kp = pykeepass.create_database(fname, pwd, kfile)
        self._export_group(kp, self._base_group, kp.root_group)
        kp.save()

    def _export_group(self, kp: pykeepass.PyKeePass,
                      group: PassGroup, kp_parent):
        """Export a group and its entries."""
        kp_group = kp.add_group(kp_parent, group.name)
        for entry in group.entries:
            if entry.password is None:
                continue
            kp.add_entry(kp_group, entry.title,
                         entry.username if entry.username else entry.title,
                         entry.password,
                         url=entry.url)
        for subgroup in group.subgroups:
            if not subgroup.entries and not subgroup.subgroups:
                continue
            self._export_group(kp, subgroup, kp_group)


def get_keyfile(keyfile: str | None == None):
    # if len(sys.argv) > 0:
    #    if sys.argv[1] == '-h':
    #        print("Usage: can provide keyfile as argument")
    #        quit()
    #    else:
    #        keyfile = sys.argv[1]
    if keyfile is not None:
        return keyfile
    else:
        answer = input("Proceeding *without* a keyfile. Are you sure? (y/N) ")
        if answer.lower() not in ("Y", "y"):
            quit()
        keyfile = None  # replace by "./keyfile" to use a file as part of the key
    return keyfile


def get_pass():
    print("Give a master password to export, <C-c> to cancel")
    mp = getpass("> HIDDEN")
    print("re-type the password for confirmation")
    cp = getpass("> HIDDEN")
    if mp == cp:
        return mp
    else:
        return get_pass()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    # prog='p2kp',
                    description='Convert pass to keepass',
                    )
    parser.add_argument('-o', '--output', default="ps_exported.kpdb",
                        help="name of the output kpdb file")
    parser.add_argument('-k', '--keyfile',
                        help="path to keyfile (for added security)")
    args = parser.parse_args()
    keyfile = get_keyfile(args.keyfile)
    print(f"About to create keypass file {args.output} using keyfile {keyfile}.")
    mp = get_pass()
    print("Reading the password store, this may take a few minutes...")
    t = time.time()
    ps = Pass()  # replace by Pass(Pass.BASE_PATH + "/subdir/") to export a subdir only
    dt = time.time() - t
    print(f"It took {dt:.2f} seconds to read all passwords.")
    # ps.print()  # this would show what is about to be exported before confirmation
    ps.export(args.output, mp, keyfile)
    print("Done.")
