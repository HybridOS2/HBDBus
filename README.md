# HBDBus

HBDBus is the data bus for device side of HybridOS.

- [Introduction](#introduction)
- [Dependencies](#dependencies)
- [Current Status](#current-status)
- [Build HBDBus for Standalone Use](#build-hbdbus-for-standalone-use)
- [TODO List](#todo-list)
- [Copying](#copying)
   + [Commercial License](#commercial-license)
   + [Special Statement](#special-statement)

## Introduction

In HybridOS, an important design idea is always implemented: data-driven.
Regardless of whether it is a single app scenario or multiple apps scenarios,
HBDBus will act as the link between HybridOS app and the underlying functional
modules; and even in the future, it will become the link between different
device nodes in the LAN.

Some ideas of HBDBus come from OpenWRT's uBus, such as passing data in JSON format.
But compared to uBus, HBDBus has the following important improvements:

- Two types of underlying connection channels are provided: local Unix Domain Socket
  and Web Socket, so that modules developed in different programming languages can
  be easily connected to HBDBus.
- Providing a basic security mechanism to determine whether an application or a remote
  node can subscribe to a specific event or call a specific procedure.
- Considering that in the future, HBDBus can provide services to other IoT device nodes
  in the local area network through Web Socket, we include host name
  information when subscribing to events and calling remote procedures.
- The redesigned HBDBus protocol can avoid deadlock when the same app plays
  different roles.

HBDBus includes the following three components:

1. HBDBus server, an executable program which runs as a daemon in the system.
1. HBDBus cmdline, an executable program which provides an interactive command line program
   for test and debugging.
1. HBDBus library, an library which provides some APIs for clients to use HBDBus easily.

For more information, please refer to:

<https://github.com/FMSoftCN/hybridos/blob/master/docs/design/hybridos-data-bus-zh.md>

## Dependencies

HBDBus depends on the following libraries:

- [PurC](https://github.com/HVML/PurC) provides support for JSON and some general utilities.
- [glib](https://github.com/GNOME/glib) provides data structure handling for C language.
- OpenSSL (optional) provides support for secure WebSocket connections.

## Current Status

- May. 2023: Version 2.0.
- Jan. 2021: Version 1.0.
- Dec. 2020: First release (version 0.9).
- Oct. 2020: Skeleton of source code.

## Build HBDBus for Standalone Use

To build HBDBus for your own usage on a generic Linux box without
the app management of HybridOS, use the following options for `cmake`:

```console
$ cmake <directory_to_source_code> -DPORT=Linux
```

## Usage

After building HBDBus, there will be two executables and one script:

1. `hbdbusd`, located in the `sbin/` directory in the root of your building tree.
   This is the daemon program of HBDBus system.
1. `hbdbuscl`, located in the `bin/` directory in the root of your building tree.
   This is a simple command line program for interacting with other programs
   connecting to HBDBus.
1. `hbdtest.hvml`, located in the `hvml/` directory in the root of your building tree.
   This is a simple HVML program for demonstrating use of HVML to interacting
   with other programs connecting to HBDBus.

To start HBDBus, you need to run `hbdbusd` first. Type the following command
in the root of your buidling tree:

```console
$ sbin/hbdbusd
```

After starting `hbdbusd`, you can run `hbdbuscl` or the HVML script `hbdtest.hvml`
to play with HBDBus.

For the detailed usage, please run `hbdbusd` or `hbdbuscl` with `-h` option.

For the description of APIs providing by HBDBus, please refer to:

[Design of HybridOS Data Bus (Chinese)](https://github.com/HybridOS2/Documents/blob/master/zh/hybridos-design-data-bus-zh.md)

## TODO List

- Version 2.2
   1. Support for WebSocket in `libhbdbus`.
   1. Support for plugins of builtin endpoints.
   1. Unit tests.

## Copying

Copyright (C) 2020 ~ 2023 FMSoft <https://www.fmsoft.cn>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Tradmarks

1) 飛漫

![飛漫](https://www.fmsoft.cn/application/files/cache/thumbnails/87f47bb9aeef9d6ecd8e2ffa2f0e2cb6.jpg)

2) FMSoft

![FMSoft](https://www.fmsoft.cn/application/files/cache/thumbnails/44a50f4b2a07e2aef4140a23d33f164e.jpg)

3) 合璧

![合璧](https://www.fmsoft.cn/application/files/4716/1180/1904/256132.jpg)
![合璧](https://www.fmsoft.cn/application/files/cache/thumbnails/9c57dee9df8a6d93de1c6f3abe784229.jpg)
![合壁](https://www.fmsoft.cn/application/files/cache/thumbnails/f59f58830eccd57e931f3cb61c4330ed.jpg)

4) HybridOS

![HybridOS](https://www.fmsoft.cn/application/files/cache/thumbnails/5a85507f3d48cbfd0fad645b4a6622ad.jpg)

5) HybridRun

![HybridRun](https://www.fmsoft.cn/application/files/cache/thumbnails/84934542340ed662ef99963a14cf31c0.jpg)

6) MiniGUI

![MiniGUI](https://www.fmsoft.cn/application/files/cache/thumbnails/54e87b0c49d659be3380e207922fff63.jpg)

7) xGUI

![xGUI](https://www.fmsoft.cn/application/files/cache/thumbnails/7fbcb150d7d0747e702fd2d63f20017e.jpg)

8) miniStudio

![miniStudio](https://www.fmsoft.cn/application/files/cache/thumbnails/82c3be63f19c587c489deb928111bfe2.jpg)

9) HVML

![HVML](https://www.fmsoft.cn/application/files/8116/1931/8777/HVML256132.jpg)

10) 呼噜猫

![呼噜猫](https://www.fmsoft.cn/application/files/8416/1931/8781/256132.jpg)

11) Purring Cat

![Purring Cat](https://www.fmsoft.cn/application/files/2816/1931/9258/PurringCat256132.jpg)

12) PurC

![PurC](https://www.fmsoft.cn/application/files/5716/2813/0470/PurC256132.jpg)

[Beijing FMSoft Technologies Co., Ltd.]: https://www.fmsoft.cn
[FMSoft Technologies]: https://www.fmsoft.cn
[FMSoft]: https://www.fmsoft.cn
[HybridOS Official Site]: https://hybridos.fmsoft.cn
[HybridOS]: https://hybridos.fmsoft.cn

[HVML]: https://github.com/HVML
[Vincent Wei]: https://github.com/VincentWei
[MiniGUI]: https://github.com/VincentWei/minigui

