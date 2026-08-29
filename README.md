# qcdm-mcp

## ALPHA — NOT TESTED ON REAL HARDWARE

This is an untested, best-effort implementation. The packet layouts were
derived from public documentation and open-source MIT/GPL projects, but this
server has **not** been run against a real Qualcomm modem. Some fields are
marked **inferred, unverified**. Writing to a device (NV, memory, EFS) can
crash the modem or brick it. Use at your own risk, on hardware you can afford
to lose, and always back up NV/EFS first.

A single-file Python **MCP (Model Context Protocol)** server that speaks the
**Qualcomm DIAG / QCDM protocol** ("Diag", "Diagnostic Monitor") over a serial
diag port. It is the sibling project to `sahara-mcp` and mirrors its style.

## Features

Exposes the following tools (all under the `diag_` prefix):

| Tool | Purpose |
| --- | --- |
| `diag_list_ports` | Enumerate serial ports (name, description, hwid) |
| `diag_version` | Modem version/build string via `DIAG_VERSION_F` + `DIAG_EXT_BUILD_ID_F` |
| `diag_nv_read` | Read a single NV item (hex payload) |
| `diag_nv_write` | Write a single NV item (WARNING: can corrupt/brick) |
| `diag_memory_peek` | Read modem memory via `DIAG_PEEKB_F` |
| `diag_memory_poke` | Write modem memory via `DIAG_POKEB_F` (WARNING; inferred layout) |
| `diag_efs_list` | List an EFS2 directory |
| `diag_efs_pull` | Copy a modem EFS file to the host |
| `diag_efs_push` | Push a host file into modem EFS + read-back verify (WARNING) |

The server talks over a serial port at 115200 baud using HDLC-style framing.

## How to expose a DIAG port

* **Rooted Android phone** — `/dev/diag` (requires root). To re-enumerate the
  phone with a usb diag port exposed (with adb still available):
  ```
  adb shell su -c 'setprop sys.usb.config diag,serial_cdev,rmnet,adb'
  ```
  It re-enumerates as a Qualcomm DIAG device (`05c6:9091`). On Linux, bind it
  with the `option` driver (`sudo modprobe option`; `echo 05c6 9091 |
  sudo tee /sys/bus/usb-serial/drivers/option1/new_id`). Only one of the
  serial nodes is the DIAG port; pass it explicitly or let the server probe.
* **USB modem / dongle** — many Qualcomm modems expose a diag pseudo-serial
  port either directly or after sending the vendor command `AT$QCDMG`. This
  is commonly `/dev/ttyUSB*` (Linux) / `COMx` (Windows).
* **Windows COM ports** — use Device Manager to find the diag port. If it is
  hidden, enable *View → Show hidden devices*. The server enumerates ports via
  `serial.tools.list_ports` and can auto-probe.

If `port` is left empty, the server probes every enumerated serial port with a
`DIAG_VERSION_F` request and uses the first that answers (so you don't have to
guess which `ttyUSB*`/`COMx` is the diag one).

## Install

Requires Python 3.8+ and the `pyproject.toml` dependencies:

```
pip install pyserial
pip install "mcp"        # or: pip install -e .
```

## Usage

Run the server (stdio transport, consumed by an MCP client):

```
python qcdm_mcp_server.py
```

Example tool invocations an agent might make:

```
diag_version(port="COM3")
diag_version(port="")                      # auto-detect
diag_nv_read(port="COM3", item_id=550)     # NV_UE_IMEI_I
diag_efs_list(port="COM3", path="/policyman")
diag_efs_pull(port="COM3", remote_path="/policyman/band_set_01.xml",
              local_path="band_set_01.xml")
diag_efs_push(port="COM3", local_path="band_set_01.xml",
              remote_path="/policyman/band_set_01.xml")
diag_memory_peek(port="COM3", address=0x40000000, length=16)
```

## Protocol notes and corrections (verified against references)

* **On-wire framing** — HDLC-like: payload + CRC-16, trailer `0x7e`; `0x7e`
  escaped as `0x7d 0x5e`, `0x7d` as `0x7d 0x5d`. CRC is the reflected
  FCS-16 (poly `0x8408`, init `0xFFFF`, complemented) — verified against the
  CRC-16/X-25 check value.
* **Command codes** (`diagcmd.h` lineage):
  `DIAG_VERSION_F = 0x00`, `DIAG_EXT_BUILD_ID_F = 0x7c`,
  `DIAG_NV_READ_F = 0x26`, `DIAG_NV_WRITE_F = 0x27`,
  `DIAG_PEEKB/POKEB = 0x02/0x05`, `DIAG_SUBSYS_CMD_F = 0x4b`,
  errors `0x13/0x14/0x15`.
* **Corrections to common guesses**: NV read/write are `0x26/0x27`, not
  `0x27/0x28`; `DIAG_SUBSYS_CMD_F` is `0x4b`, not `0x54`; EFS subcommands are
  the 0-based `0..15` ids (HELLO=0, OPENDIR=11, READDIR=12, STAT=15, …), not
  the `0x2011+` offset family that appears in some older documentation. See
  `qcdm_mcp_server.py` comments.
* **Length limits** — legacy serial DIAG frames are capped around 4 KB
  (`DIAG_MAX_PKT_LEN`); larger payloads are split into small chunks (EFS
  transfers use 1 KB chunks, the negotiated window is 1 MiB). Newer transports
  add a `multi_pkt` wrapper for large frames; this server stays on the
  serial/HDLC path and does not use it.
* **Inferred/unverified**: the exact split of the NV read payload between data
  and trailing status byte, the memory-poke response layout, and the variables
  inside the `readdir` response.

## References and licensing

* P1sec **QCSuper** — *The Diag protocol* writeup. GPL-3.0. Consulted for
  protocol facts only; **no GPL code is imported or copied.**
  https://github.com/P1sec/QCSuper
* grmrgecko/**qcdm-efs2** — MIT (Copyright (c) 2026 Mr. Gecko's Media).
  Source of the EFS2 envelope/subcommand response offsets.
  https://github.com/grmrgecko/qcdm-efs2
* JohnBel/**EfsTools** — packet layouts and opcodes (behavioral reference).
  https://github.com/JohnBel/EfsTools
* Wireshark `packet-qcdiag` / osmo-qcdiag / quectel QLog — `diagcmd.h`
  command-code lineage (facts).

This project is licensed under the **GPL-3.0 license**. See `LICENSE`.
Copyright (c) 2026 libertyrights. Our own code is GPL-3.0; the references
above were used for protocol facts only and retain their own licenses.