[![Build](https://github.com/OlekMazur/alsa-http-streaming-server/actions/workflows/makefile.yml/badge.svg)](https://github.com/OlekMazur/alsa-http-streaming-server/actions/workflows/makefile.yml)

ALSA HTTP streaming server
==========================

A program which records audio from given ALSA device and sends it as WAV
to a bunch of clients connected to built-in very simple HTTP 1.0 server.
It can also play the recorded audio via given ALSA device (loopback) --
this is controlled via pipe.
Audio is recorded only when at least one client receives it.
Samples are internally kept in a ring buffer.
Connections to clients which cannot keep up receiving data in real time
are terminated automatically.

The program supports optional software volume control
(constant DC bias correction and amplitude multiplication).

It also supports triggering keep-alive file when audio is needed --
useful e.g. to keep V4L2 radio tuner tuned.

Example
-------
Sharing audio from *SAA7134* FM tuner built into *KNC ONE* PCI card:
```
umask 0137
exec chpst -u streamer: streamer -C hw:0,0 --info info.txt --status status.txt --keep-alive-what keep --keep-alive-to tuner/ctl --channels 2 --vol 2048+12888
```

Documentation
-------------

See [documentation].

Notice
------

ALSA HTTP streaming server @copyright © 2023 Aleksander Mazur

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the [GNU General Public License]
along with this program.  If not, see <https://www.gnu.org/licenses/>.

[GNU General Public License]: LICENSE.md
[documentation]: https://olekmazur.github.io/alsa-http-streaming-server
