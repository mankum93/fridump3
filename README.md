# fridump3
Fridump is an open source memory dumping tool, primarily aimed at penetration testers and developers. It uses the Frida framework to dump accessible memory addresses from any platform supported. It can be used from a Windows, Linux or macOS system to dump the memory of an iOS, Android or Windows application.

This project is based on the following project: [https://github.com/Nightbringer21/fridump](https://github.com/Nightbringer21/fridump) and the pending PR concerning Python3 support (especially from [georgepetz](https://github.com/georgepetz)). Additionally, network support has been added in addition to USB support. The embedded Frida agent applies several anti anti-debugging tricks, sanitising `/proc` reads and common system calls so the tooling can operate undetected while exposing the same RPC interface for memory dumping.

FYI: I will destroy this repo is the Fridump author will integrate the pending PR concerning Python3 support.

Usage
---

```
usage: fridump [-h] [-o dir] [-u] [-H HOST] [-v] [-r] [-s] [--max-size bytes] process

positional arguments:
  process               the process that you will be injecting to

optional arguments:
  -h, --help            show this help message and exit
  -o dir, --out dir     provide full output directory path. (def: 'dump')
  -u, --usb             device connected over usb
  -H HOST, --host HOST  device connected over IP
  -v, --verbose         verbose
  -r, --read-only       dump read-only parts of memory. More data, more errors
  -s, --strings         run strings on all dump files. Saved in output dir.
  --max-size bytes      maximum size of dump file in bytes (def: 20971520)
```
