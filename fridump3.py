import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging

logo = """
        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \| '_ \\
        | | | |  | | (_| | |_| | | | | | | |_) |
        \_| |_|  |_|\__,_|\__,_|_| |_| |_| .__/
                                         | |
                                         |_|
        """


# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument(
        'process', help='the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, help='provide full output directory path. (def: \'dump\')',
                        metavar="dir")
    parser.add_argument('-u', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-H', '--host', type=str,
                        help='device connected over IP')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, help='maximum size of dump file in bytes (def: 20971520)',
                        metavar="bytes")
    args = parser.parse_args()
    return args


print(logo)

arguments = MENU()

# Define Configurations
APP_NAME = utils.normalize_app_name(appName=arguments.process)
DIRECTORY = ""
USB = arguments.usb
NETWORK=False
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.host is not None:
  NETWORK=True
  IP=arguments.host

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_NAME)
    elif NETWORK:
        session = frida.get_device_manager().add_remote_device(IP).attach(APP_NAME)
    else:
        session = frida.attach(APP_NAME)
except Exception as e:
    print(str(e))
    sys.exit()


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print("Output directory is set to: " + DIRECTORY)
    else:
        print("The selected output directory does not exist!")
        sys.exit(1)

else:
    print("Current Directory: " + str(os.getcwd()))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print("Output directory is set to: " + DIRECTORY)
    if not os.path.exists(DIRECTORY):
        print("Creating directory...")
        os.makedirs(DIRECTORY)

mem_access_viol = ""

print("Starting Memory dump...")

# Load the anti-anti-debugging agent
def on_message(message, data):
    print("[on_message] message:", message, "data:", data)


agent_source = r"""
'use strict';

const libc = "libc.so";
const NR_PTRACE = (() => {
  switch (Process.arch) {
    case "arm64": return 117;
    case "arm":   return 26;
    case "x64":   return 101;
    case "ia32":  return 26;
    default:      return 117;
  }
})();

setImmediate(() => {
  hookPtrace();
  hookSyscallPtrace();
  hookPrctlDumpable();
  scrubProcStatusTracerPid();
  hideFridaFromProcMaps();
  spoofBuildProps();
  hookJavaDebugLies();
});

function hookPtrace() {
  const p = Module.findExportByName(libc, "ptrace");
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) { this.req = args[0].toInt32(); },
    onLeave(retval) { retval.replace(0); }
  });
}

function hookSyscallPtrace() {
  const p = Module.findExportByName(libc, "syscall");
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) { this.nr = args[0].toInt32(); },
    onLeave(retval) { if (this.nr === NR_PTRACE) retval.replace(0); }
  });
}

const PR_GET_DUMPABLE = 3;
const PR_SET_DUMPABLE = 4;
function hookPrctlDumpable() {
  const p = Module.findExportByName(libc, "prctl");
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) { this.opt = args[0].toInt32(); },
    onLeave(retval) {
      if (this.opt === PR_GET_DUMPABLE) retval.replace(1);
      else if (this.opt === PR_SET_DUMPABLE) retval.replace(0);
    }
  });
}

function scrubProcStatusTracerPid() {
  const openat = Module.findExportByName(libc, "openat");
  const open_  = Module.findExportByName(libc, "open");
  const read   = Module.findExportByName(libc, "read");
  const statusFDs = new Set();

  function trackOpen(which, pathArgIndex) {
    if (!which) return;
    Interceptor.attach(which, {
      onEnter(args) {
        this.path = null;
        try { this.path = args[pathArgIndex].readUtf8String(); } catch (_) {}
      },
      onLeave(retval) {
        const fd = retval.toInt32();
        if (fd >= 0 && this.path && this.path.indexOf("/proc/self/status") !== -1) {
          statusFDs.add(fd);
        }
      }
    });
  }

  trackOpen(openat, 1);
  trackOpen(open_, 0);

  if (read) {
    Interceptor.attach(read, {
      onEnter(args) {
        this.fd  = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        try {
          if (retval.toInt32() > 0 && statusFDs.has(this.fd)) {
            const s = this.buf.readUtf8String(retval.toInt32());
            if (s && s.indexOf("TracerPid:") !== -1) {
              const fixed = s.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
              Memory.writeUtf8String(this.buf, fixed);
              retval.replace(fixed.length);
            }
          }
        } catch (_) {}
      }
    });
  }
}

function hideFridaFromProcMaps() {
  const openat = Module.findExportByName(libc, "openat");
  const open_  = Module.findExportByName(libc, "open");
  const read   = Module.findExportByName(libc, "read");
  const mapsFDs = new Set();
  const BAD = [/frida/i, /gadget/i, /gum[-_.]/i, /frida-agent/i];

  function trackOpen(which, pathArgIndex) {
    if (!which) return;
    Interceptor.attach(which, {
      onEnter(args) {
        this.path = null;
        try { this.path = args[pathArgIndex].readUtf8String(); } catch (_) {}
      },
      onLeave(retval) {
        const fd = retval.toInt32();
        if (fd >= 0 && this.path && this.path.indexOf("/proc/self/maps") !== -1) {
          mapsFDs.add(fd);
        }
      }
    });
  }

  trackOpen(openat, 1);
  trackOpen(open_, 0);

  if (read) {
    Interceptor.attach(read, {
      onEnter(args) {
        this.fd  = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
      },
      onLeave(retval) {
        try {
          if (retval.toInt32() > 0 && mapsFDs.has(this.fd)) {
            const s = this.buf.readUtf8String(retval.toInt32());
            if (s) {
              const cleaned = s.split("\n").filter(line => !BAD.some(rx => rx.test(line))).join("\n");
              if (cleaned.length !== s.length) {
                Memory.writeUtf8String(this.buf, cleaned);
                retval.replace(cleaned.length);
              }
            }
          }
        } catch (_) {}
      }
    });
  }
}

function spoofBuildProps() {
  const propGet = Module.findExportByName(libc, "__system_property_get");
  if (!propGet) return;
  Interceptor.attach(propGet, {
    onEnter(args) {
      this.name = args[0].readUtf8String();
      this.buf  = args[1];
    },
    onLeave(retval) {
      try {
        if (this.name === "ro.debuggable") {
          Memory.writeUtf8String(this.buf, "0");
          retval.replace(1);
        } else if (this.name === "ro.secure") {
          Memory.writeUtf8String(this.buf, "1");
          retval.replace(1);
        }
      } catch (_) {}
    }
  });
}

function hookJavaDebugLies() {
  if (!Java.available) return;
  Java.perform(() => {
    try {
      const Debug = Java.use("android.os.Debug");
      Debug.isDebuggerConnected.implementation = () => false;
      Debug.waitingForDebugger.implementation  = () => false;
    } catch (_) {}
    try {
      const VmDebug = Java.use("dalvik.system.VMDebug");
      VmDebug.isDebuggerConnected.implementation = () => false;
      VmDebug.debuggerConnected.implementation   = () => false;
    } catch (_) {}
  });
}

rpc.exports = {
  enumerateRanges: function (prot) {
    return Process.enumerateRangesSync(prot);
  },
  readMemory: function (address, size) {
    return Memory.readByteArray(ptr(address), size);
  }
};
"""

script = session.create_script(agent_source)
script.on("message", on_message)
script.load()

agent = script.exports_sync
ranges = agent.enumerate_ranges(PERMS)

if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

i = 0
l = len(ranges)

# Performing the memory dump
for range in ranges:
    logging.debug("Base Address: " + str(range["base"]))
    logging.debug("")
    logging.debug("Size: " + str(range["size"]))
    if range["size"] > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(
            agent, range["base"], range["size"], MAX_SIZE, mem_access_viol, DIRECTORY)
        continue
    mem_access_viol = dumper.dump_to_file(
        agent, range["base"], range["size"], mem_access_viol, DIRECTORY)
    i += 1
    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)

# Run Strings if selected

if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    print("Running strings on all files:")
    for f1 in files:
        utils.strings(f1, DIRECTORY)
        i += 1
        utils.printProgress(i, l, prefix='Progress:',
                            suffix='Complete', bar=50)
print("Finished!")
#raw_input('Press Enter to exit...')
