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

```
$ cmake <directory_to_source_code>
```

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

