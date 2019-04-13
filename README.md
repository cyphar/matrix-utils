## matrix-utils ##

Random matrix utilities.

### `megolm_backup.py` ###

This script can be used to modify your offline megolm key backups from a shell.
The main use of this is to filter what keys you'd like to share with another
user (let's say you have a 1:1 chat, and the other user lost all their keys and
you need to give them access without giving access to all of your rooms).
[There is currently no Riot-based tooling for this][riotweb-issue6454], so this
script can help in the meantime.

I've tested the output and input format with my own room keys and it has worked
so far.

```
usage: megolm_backup.py [-h] (--into | --from) [file]

Operate on megolm session backups.

positional arguments:
  file        Backup text file (- for stdin).

optional arguments:
  -h, --help  show this help message and exit
  --into      Encrypt and represent file as a megolm session backup.
  --from      Decrypt the given megolm session and output the contents.
```

Using the above example, let's say we want to only get session keys of the room
`!foo:matrix.org`. You can do this fairly easily with [`jq`][jq]:

```bash
% megolm_backup.py --from riot-keys.py |
	jq 'map(select(.room_id == "!foo:matrix.org"))' |
	megolm_backup.py --into > new-riot-keys.txt
```

You need to have PyCrypto installed in order for this script to work.

[riotweb-issue6454]: https://github.com/vector-im/riot-web/issues/6454
[jq]: https://stedolan.github.io/jq/

### License ###

matrix-utils is licensed under the GNU General Public License version 3 or
later.

```
Copyright (C) 2019 Aleksa Sarai <cyphar@cyphar.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
