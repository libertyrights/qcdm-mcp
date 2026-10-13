# qcdm-mcp
# Copyright (C) 2026 libertyrights
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.

"""qcdm-mcp: a Model Context Protocol server for the Qualcomm DIAG/QCDM protocol.

A native, dependency-light implementation of the Qualcomm DIAG protocol
(also called QCDM or "Diagnostic Monitor") over a serial diag port, exposed
to LLM agents through MCP tools. It talks to a rooted Android phone's
``/dev/diag`` or a USB modem's diag pseudo-serial port (``AT$QCDMG``).

Protocol facts are derived from public documentation and implementations:

* Framing (HDLC-like escape framing, ``0x7e`` trailer, CRC-16) from the P1sec
  QCSuper "The Diag protocol" writeup. QCSuper is GPL-3.0 and was consulted
  for protocol facts only; no GPL code is imported or copied.
* DIAG command codes follow the ``diagcmd.h`` lineage as mirrored in
  Wireshark's packet-qcdiag, osmo-qcdiag, quectel QLog and JohnBel/EfsTools
  (QcdmCommand enum).
* EFS2 subsystem handling (subsystem 19 envelopes, HELLO/OPEN/READ/WRITE/
  opendir/readdir/stat packet layouts) replicates the layouts used by
  grmrgecko/qcdm-efs2 (MIT, Copyright (c) 2026 Mr. Gecko's Media), which in
  turn replicate JohnBel/EfsTools.

No GPL code is imported or linked. See README for wiring and safety notes.
"""

from __future__ import annotations

import logging
import struct
import sys
import time
from typing import Dict, List, Optional

logger = logging.getLogger("qcdm-mcp")

# ---------------------------------------------------------------------------
# DIAG protocol constants
# ---------------------------------------------------------------------------

# DIAG command codes (diagcmd.h lineage; see module docstring).
DIAG_VERSION_F = 0x00    # legacy version query (DIAG_VERNO_F)
DIAG_ESN_F = 0x01        # electronic serial number
DIAG_PEEKB_F = 0x02      # memory peek, byte
DIAG_PEEKW_F = 0x03      # memory peek, word
DIAG_PEEKD_F = 0x04      # memory peek, dword
DIAG_POKEB_F = 0x05      # memory poke, byte
DIAG_POKEW_F = 0x06      # memory poke, word
DIAG_POKED_F = 0x07      # memory poke, dword
DIAG_BAD_CMD_F = 0x13    # synchronous error replies
DIAG_BAD_PARM_F = 0x14
DIAG_BAD_LEN_F = 0x15
DIAG_DIAG_VER_F = 0x1C   # diag protocol version (uint16)
DIAG_NV_READ_F = 0x26    # NV read  (task brief guessed 0x27; verified 0x26)
DIAG_NV_WRITE_F = 0x27   # NV write (task brief guessed 0x28; verified 0x27)
DIAG_SUBSYS_CMD_F = 0x4B # subsystem command (task brief guessed 0x54; verified 0x4B)
DIAG_EXT_BUILD_ID_F = 0x7C

_ERROR_CMDS = (DIAG_BAD_CMD_F, DIAG_BAD_PARM_F, DIAG_BAD_LEN_F)

# DIAG subsystem ids (QcdmSubSystem enum).
DIAG_SUBSYS_EFS = 0x13   # 19, EFS2 file system

# EFS2 subcommand codes. These are 0-based ids (not the "0x2011+ family"
# offset seen in some older docs); the on-wire values are little-endian
# uint16s as sent by JohnBel/EfsTools and grmrgecko/qcdm-efs2.
EFS2_HELLO = 0x00
EFS2_QUERY = 0x01
EFS2_OPEN = 0x02
EFS2_CLOSE = 0x03
EFS2_READ = 0x04
EFS2_WRITE = 0x05
EFS2_UNLINK = 0x08
EFS2_MKDIR = 0x09
EFS2_OPENDIR = 0x0B
EFS2_READDIR = 0x0C
EFS2_CLOSEDIR = 0x0D
EFS2_STAT = 0x0F

EFS_O_RDONLY = 0x0000
EFS_O_WRONLY = 0x0001
EFS_O_CREAT = 0x0100

EFS_FILE_TYPE_NAMES = {0: "file", 1: "dir", 2: "link", 3: "immovable", 15: "item"}
EFS_ERROR_NAMES = {
    0x40000001: "FS_DIAG_INCONSISTENT_STATE",
    0x40000002: "FS_DIAG_INVALID_SEQ_NO",
    0x40000003: "FS_DIAG_DIR_NOT_OPEN",
    0x40000004: "FS_DIAG_DIRENT_NOT_FOUND",
    0x40000005: "FS_DIAG_INVALID_PATH",
    0x40000006: "FS_DIAG_PATH_TOO_LONG",
    0x40000007: "FS_DIAG_TOO_MANY_OPEN_DIRS",
    0x40000008: "FS_DIAG_INVALID_DIR_ENTRY",
    0x40000009: "FS_DIAG_TOO_MANY_OPEN_FILES",
}

# Framing / transport limits.
HDLC_TRAILER = 0x7E
HDLC_ESCAPE = 0x7D
DIAG_SERIAL_BAUD = 115200
DIAG_MAX_PKT_LEN = 4096   # legacy serial single-frame payload limit
EFS_CHUNK_SIZE = 1024     # transfers are chunked well below the 4 KB limit
EFS_WINDOW = 0x100000     # negotiated EFS window size (1 MiB)

# ---------------------------------------------------------------------------
# CRC-16 / HDLC framing helpers (FCS-16, reflected poly 0x8408, init 0xFFFF)
# ---------------------------------------------------------------------------

_CRC16_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x8408 if (_c & 1) else (_c >> 1)
    _CRC16_TAB.append(_c)


def fcs16(data: bytes) -> int:
    fcs = 0xFFFF
    for b in data:
        fcs = (fcs >> 8) ^ _CRC16_TAB[(fcs ^ b) & 0xFF]
    return (~fcs) & 0xFFFF


def hdlc_encode(payload: bytes) -> bytes:
    """Encapsulate a raw DIAG payload with CRC-16 + escaping + trailer."""
    frame = payload + struct.pack("<H", fcs16(payload))
    out = bytearray()
    for b in frame:
        if b == HDLC_TRAILER:
            out += b"\x7d\x5e"
        elif b == HDLC_ESCAPE:
            out += b"\x7d\x5d"
        else:
            out.append(b)
    out.append(HDLC_TRAILER)
    return bytes(out)


def hdlc_decode(frame: bytes) -> bytes:
    out = bytearray()
    esc = False
    for b in frame:
        if esc:
            out.append(b ^ 0x20)
            esc = False
        elif b == HDLC_ESCAPE:
            esc = True
        else:
            out.append(b)
    return bytes(out)


def _cstr(b: bytes) -> str:
    return b.split(b"\x00", 1)[0].decode("ascii", "replace")


def _efs_err_name(err: int) -> str:
    return EFS_ERROR_NAMES.get(err, str(err))


class QcdmError(Exception):
    """Protocol-level or transport-level error."""


# ---------------------------------------------------------------------------
# Serial transport (pyserial)
# ---------------------------------------------------------------------------


class DiagTransport:
    def __init__(self, port: str, baudrate: int = DIAG_SERIAL_BAUD,
                 timeout: float = 0.5) -> None:
        import serial

        self.port = port
        try:
            self.serial = serial.Serial(port, baudrate, timeout=timeout,
                                        write_timeout=1.0)
            self.serial.reset_input_buffer()
        except serial.SerialException as exc:
            raise QcdmError("could not open serial port %s: %s" % (port, exc))

    def _read_byte(self):
        try:
            return self.serial.read(1)
        except Exception as exc:
            raise QcdmError("serial read failed on %s: %s" % (self.port, exc))

    def read_frame(self, timeout: float = 4.0) -> bytes:
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            b = self._read_byte()
            if not b:
                continue
            if b[0] == HDLC_TRAILER:
                if not buf:
                    continue  # leading terminator
                dec = hdlc_decode(bytes(buf))
                buf = bytearray()
                if len(dec) < 3:
                    continue
                payload, crc = dec[:-2], struct.unpack("<H", dec[-2:])[0]
                if fcs16(payload) != crc:
                    logger.debug("partial/corrupt DIAG frame, re-syncing")
                    continue
                return payload
            else:
                buf.append(b[0])
        raise QcdmError("timed out waiting for a DIAG frame on %s" % self.port)

    def write_frame(self, payload: bytes) -> None:
        frame = hdlc_encode(payload)
        try:
            n = self.serial.write(frame)
        except Exception as exc:
            raise QcdmError("serial write failed on %s: %s" % (self.port, exc))
        if n != len(frame):
            raise QcdmError("short write on %s" % self.port)
        try:
            self.serial.flush()
        except Exception as exc:
            raise QcdmError("serial flush failed on %s: %s" % (self.port, exc))

    def request(self, cmd: int, body: bytes = b"", timeout: float = 4.0,
                match: Optional[object] = None) -> bytes:
        """Send a request and return the matching synchronous response frame."""
        self.write_frame(bytes([cmd]) + body)
        deadline = time.time() + timeout
        while time.time() < deadline:
            p = self.read_frame(timeout=max(0.05, deadline - time.time()))
            if not p:
                continue
            if p[0] == cmd:
                return p
            if p[0] in _ERROR_CMDS:
                raise QcdmError("DIAG command 0x%02X rejected with 0x%02X"
                                % (cmd, p[0]))
            if match is not None and match(p):
                return p
            # otherwise an asynchronous log/message frame: drop and keep reading
        raise QcdmError("no matching response for DIAG command 0x%02X" % cmd)

    def subsys(self, subsystem: int, subcmd: int, body: bytes = b"",
               timeout: float = 4.0) -> bytes:
        """Send a DIAG_SUBSYS_CMD_F request, matching the full envelope reply."""
        envelope = struct.pack("<BBH", DIAG_SUBSYS_CMD_F, subsystem, subcmd)
        want_lo, want_hi = subcmd & 0xFF, (subcmd >> 8) & 0xFF

        def _match(p: bytes) -> bool:
            return (len(p) >= 4 and p[1] == subsystem
                    and p[2] == want_lo and p[3] == want_hi)

        return self.request(DIAG_SUBSYS_CMD_F, envelope + body,
                            timeout=timeout, match=_match)

    def close(self) -> None:
        try:
            self.serial.close()
        except Exception:
            pass

    # -- DIAG_VERSION_F / DIAG_EXT_BUILD_ID_F ------------------------------

    def version(self) -> Dict[str, object]:
        out: Dict[str, object] = {}
        resp = self.request(DIAG_VERSION_F, b"", timeout=2.0)
        body = resp[1:]
        if len(body) >= 54:
            # DiagVernoResponse: comp_date(11) comp_time(8) rel_date(11)
            # rel_time(8) ver_dir(8) scm(1) cai_rev(1) model(1) firm_rev(2)
            # slot_cycle(1) hw_maj(1) hw_min(1)
            comp = ("%s %s" % (_cstr(body[0:11]), _cstr(body[11:19]))).strip()
            rel = ("%s %s" % (_cstr(body[19:30]), _cstr(body[30:38]))).strip()
            firm_rev = struct.unpack_from("<H", body, 49)[0]
            out["compilation"] = comp
            out["release"] = rel
            out["version_directory"] = _cstr(body[38:46])
            out["mobile_firmware_revision"] = firm_rev
            out["mobile_model"] = body[48]
            out["hardware_revision"] = "%u.%u" % (body[52], body[53])
        out["verno_raw_hex"] = body.hex()

        try:
            ext = self.request(DIAG_EXT_BUILD_ID_F, b"", timeout=2.0)
            body2 = ext[1:]
            if len(body2) >= 11:
                msm_hw_version = struct.unpack_from("<I", body2, 3)[0]
                model_id = struct.unpack_from("<I", body2, 7)[0]
                strings = body2[11:].split(b"\x00")
                out["build_id"] = (_cstr(strings[0]) if strings else "")
                if len(strings) > 1:
                    out["model_string"] = _cstr(strings[1])
                out["msm_hw_version"] = "0x%08X" % msm_hw_version
                out["mobile_model_id"] = "0x%08X" % model_id
        except QcdmError:
            out["build_id"] = None
        return out

    # -- DIAG_NV_READ_F / DIAG_NV_WRITE_F ----------------------------------

    def nv_read(self, item_id: int) -> Dict[str, object]:
        resp = self.request(DIAG_NV_READ_F, struct.pack("<H", item_id & 0xFFFF))
        body = resp[1:]
        out: Dict[str, object] = {"item_id": item_id}
        if len(body) >= 4:
            # Verified envelope slots; exact data-vs-status split is best
            # inferred, unverified on real hardware: item(2) payload[..] status(1)
            out["reported_item_id"] = struct.unpack_from("<H", body, 0)[0]
            out["status"] = body[-1]
            data = body[2:-1]
            out["data_hex"] = data.hex()
            out["data_length"] = len(data)
        else:
            out["raw_hex"] = body.hex()
        return out

    def nv_write(self, item_id: int, data: bytes) -> Dict[str, object]:
        resp = self.request(DIAG_NV_WRITE_F,
                            struct.pack("<H", item_id & 0xFFFF) + data)
        body = resp[1:]
        out: Dict[str, object] = {"item_id": item_id, "written": len(data)}
        if len(body) >= 3:
            out["reported_item_id"] = struct.unpack_from("<H", body, 0)[0]
            out["status"] = body[-1]
        out["raw_hex"] = body.hex()
        return out

    # -- memory peek / poke ------------------------------------------------

    def memory_peek(self, address: int, length: int) -> Dict[str, object]:
        length = max(1, min(length, 0x1000))
        resp = self.request(DIAG_PEEKB_F,
                            struct.pack("<IH", address & 0xFFFFFFFF, length))
        body = resp[1:]
        out: Dict[str, object] = {"address": address, "requested": length}
        if len(body) >= 6:
            read_addr = struct.unpack_from("<I", body, 0)[0]
            got = struct.unpack_from("<H", body, 4)[0]
            data = body[6:6 + got]
            out["read_address"] = read_addr
            out["length"] = got
            out["data_hex"] = data.hex()
        else:
            out["raw_hex"] = body.hex()
        return out

    def memory_poke(self, address: int, data: bytes) -> Dict[str, object]:
        # Layout inferred, unverified: address(4) length(2) data[..];
        # reply address(4) length(2) status(1).
        resp = self.request(DIAG_POKEB_F,
                            struct.pack("<IH", address & 0xFFFFFFFF,
                                        len(data)) + data)
        body = resp[1:]
        out: Dict[str, object] = {"address": address, "written": len(data)}
        if len(body) >= 7:
            out["poked_address"] = struct.unpack_from("<I", body, 0)[0]
            out["status"] = body[6]
        out["raw_hex"] = body.hex()
        return out

    # -- EFS2 ---------------------------------------------------------------

    def _efs_hello(self) -> int:
        body = (struct.pack("<IIIIIIiii",
                            EFS_WINDOW, EFS_WINDOW, EFS_WINDOW,
                            EFS_WINDOW, EFS_WINDOW, EFS_WINDOW,
                            1, 1, 1) + b"\xff\xff\xff\xff")
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_HELLO, body)
        return struct.unpack_from("<i", p, 28)[0] if len(p) >= 32 else -1

    def efs_opendir(self, name: str):
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_OPENDIR,
                        name.encode("ascii") + b"\x00", timeout=6.0)
        d = struct.unpack_from("<i", p, 4)[0]
        err = struct.unpack_from("<i", p, 8)[0]
        return d, err

    def efs_readdir(self, d: int, seq: int):
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_READDIR,
                        struct.pack("<ii", d, seq), timeout=6.0)
        # Offsets are from grmrgecko/qcdm-efs2 (MIT): after the 4-byte
        # envelope + 8 bytes of echo/padding: err(4) etype(4) [..] size(4) [..] name.
        err = struct.unpack_from("<i", p, 12)[0]
        etype = struct.unpack_from("<i", p, 16)[0]
        size = struct.unpack_from("<i", p, 24)[0]
        name = p[40:].split(b"\x00", 1)[0].decode("ascii", "replace")
        return err, etype, size, name

    def efs_closedir(self, d: int) -> None:
        self.subsys(DIAG_SUBSYS_EFS, EFS2_CLOSEDIR, struct.pack("<i", d),
                    timeout=6.0)

    def efs_stat(self, name: str):
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_STAT,
                        name.encode("ascii") + b"\x00", timeout=6.0)
        err = struct.unpack_from("<i", p, 4)[0]
        mode = struct.unpack_from("<i", p, 8)[0]
        size = struct.unpack_from("<i", p, 12)[0]
        return err, mode, size

    def efs_open(self, name: str, flags: int, perm: int):
        body = struct.pack("<ii", flags, perm) + name.encode("ascii") + b"\x00"
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_OPEN, body, timeout=6.0)
        fd = struct.unpack_from("<i", p, 4)[0]
        err = struct.unpack_from("<i", p, 8)[0]
        return fd, err

    def efs_close(self, fd: int) -> None:
        self.subsys(DIAG_SUBSYS_EFS, EFS2_CLOSE, struct.pack("<i", fd),
                    timeout=6.0)

    def efs_read(self, fd: int, size: int, offset: int):
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_READ,
                        struct.pack("<iII", fd, size, offset), timeout=6.0)
        nread = struct.unpack_from("<i", p, 12)[0]
        err = struct.unpack_from("<i", p, 16)[0]
        return err, p[20:20 + max(0, nread)]

    def efs_write(self, fd: int, offset: int, chunk: bytes):
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_WRITE,
                        struct.pack("<iI", fd, offset) + chunk, timeout=6.0)
        nwr = struct.unpack_from("<i", p, 12)[0]
        err = struct.unpack_from("<i", p, 16)[0]
        return err, nwr

    def efs_unlink(self, name: str) -> int:
        p = self.subsys(DIAG_SUBSYS_EFS, EFS2_UNLINK,
                        name.encode("ascii") + b"\x00", timeout=6.0)
        return struct.unpack_from("<i", p, 4)[0]

    def efs_list(self, path: str) -> Dict[str, object]:
        entries: List[Dict[str, object]] = []
        d, err = self.efs_opendir(path)
        if err != 0 or d < 0:
            raise QcdmError("opendir %s err=%d (%s)"
                            % (path, err, _efs_err_name(err)))
        seq = 1
        try:
            while True:
                err, etype, size, name = self.efs_readdir(d, seq)
                if err != 0 or not name:
                    break
                entries.append({
                    "name": name,
                    "type": EFS_FILE_TYPE_NAMES.get(etype, str(etype)),
                    "size": size,
                })
                seq += 1
        finally:
            self.efs_closedir(d)
        return {"path": path, "entries": entries, "count": len(entries)}

    def efs_read_file(self, name: str) -> bytes:
        err, mode, size = self.efs_stat(name)
        if err != 0:
            raise QcdmError("stat %s err=%d (%s)"
                            % (name, err, _efs_err_name(err)))
        fd, err = self.efs_open(name, EFS_O_RDONLY, 0)
        if err != 0 or fd < 0:
            raise QcdmError("open(r) %s err=%d (%s)"
                            % (name, err, _efs_err_name(err)))
        data = bytearray()
        off = 0
        try:
            while off < size:
                err, chunk = self.efs_read(fd, min(EFS_CHUNK_SIZE, size - off), off)
                if err != 0:
                    raise QcdmError("read %s err=%d (%s)"
                                    % (name, err, _efs_err_name(err)))
                if not chunk:
                    break
                data += chunk
                off += len(chunk)
        finally:
            self.efs_close(fd)
        return bytes(data)

    def efs_write_file(self, name: str, data: bytes) -> int:
        err, mode, size = self.efs_stat(name)
        if err == 0:
            err = self.efs_unlink(name)
            if err != 0:
                raise QcdmError("unlink %s err=%d (%s)"
                                % (name, err, _efs_err_name(err)))
        fd, err = self.efs_open(name, EFS_O_WRONLY | EFS_O_CREAT, 0o777)
        if err != 0 or fd < 0:
            raise QcdmError("open(w) %s err=%d (%s)"
                            % (name, err, _efs_err_name(err)))
        off = 0
        try:
            while off < len(data):
                chunk = data[off:off + EFS_CHUNK_SIZE]
                err, nwr = self.efs_write(fd, off, chunk)
                if err != 0 or nwr <= 0:
                    raise QcdmError(
                        "write %s err=%d nwr=%d (%s)"
                        % (name, err, nwr, _efs_err_name(err)))
                off += nwr
        finally:
            self.efs_close(fd)
        return off


# ---------------------------------------------------------------------------
# MCP tool surface
# ---------------------------------------------------------------------------

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None


def _require() -> None:
    if FastMCP is None:
        raise SystemExit("mcp SDK not installed. Run `pip install -e .`.")
    try:
        import serial  # noqa: F401
    except ImportError:
        raise QcdmError(
            "pyserial is not installed. Run `pip install pyserial`."
        )


def _list_ports() -> List[dict]:
    try:
        from serial.tools import list_ports
    except ImportError as exc:
        raise QcdmError(
            "pyserial is not installed. Run `pip install pyserial`."
        ) from exc
    return [
        {"name": p.device, "description": p.description, "hwid": p.hwid or ""}
        for p in list_ports.comports()
    ]


def _open(port: str = "") -> DiagTransport:
    _require()
    if port:
        return DiagTransport(port)
    for info in _list_ports():
        try:
            t = DiagTransport(info["name"])
            try:
                t.write_frame(bytes([DIAG_VERSION_F]))
                resp = t.read_frame(timeout=1.2)
                if resp and resp[0] == DIAG_VERSION_F:
                    return t
            finally:
                t.close()
        except QcdmError:
            continue
    raise QcdmError(
        "no responding DIAG port found. Expose a diag port first: "
        "rooted phone `/dev/diag`, `setprop sys.usb.config "
        "diag,serial_cdev,rmnet,adb`, or a modem in diag mode (`AT$QCDMG`). "
        "Pass an explicit `port=` (COM3, /dev/ttyUSB0) to skip probing."
    )


def _with_diag(port: str, fn):
    d = _open(port)
    try:
        return fn(d)
    finally:
        d.close()


def diag_list_ports() -> list:
    """Enumerate serial ports the DIAG device may appear on."""
    try:
        _require()
        return _list_ports()
    except QcdmError as exc:
        return [{"error": str(exc)}]


def diag_version(port: str = "") -> dict:
    """Read the modem version/build string via the DIAG version queries.

    `port` is the serial port (\"COM3\", \"/dev/ttyUSB0\"). Leave empty
    to auto-detect by probing enumerated ports.
    """
    try:
        return _with_diag(port, lambda d: d.version())
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_nv_read(port: str = "", item_id: int = 0) -> dict:
    """Read a single NV item (hex-encoded payload in the response).

    `item_id` is the NV item number (e.g. IMEI / NV_UE_IMEI_I = 550).
    """
    try:
        def do(d: DiagTransport):
            return d.nv_read(item_id)
        return _with_diag(port, do)
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_nv_write(port: str = "", item_id: int = 0, data: str = "",
                  dry_run: bool = True, confirm: bool = False) -> dict:
    """Write a single NV item (MODEM-WRITING; guarded).

    WARNING: writing NV items can corrupt the modem or brick it. Only
    write values you fully understand, and back up NV first.

    Refuses to open the serial port unless BOTH ``dry_run=False`` AND
    ``confirm=True`` are passed; with the defaults it returns a dry-run
    payload describing what it *would* write and touches nothing.

    `data` is a hex string, e.g. \"01020304050607\".
    """
    would_do = {"port": port, "item_id": item_id, "data": data}
    if dry_run or not confirm:
        return {"dry_run": True, "executed": False, "would_do": would_do,
                "message": ("DRY RUN \u2014 nothing written; set dry_run=False "
                            "and confirm=True to proceed.")}
    try:
        raw = bytes.fromhex(data)
    except ValueError as exc:
        return {"error": "data must be a valid hex string: %s" % exc}
    try:
        def do(d: DiagTransport):
            return d.nv_write(item_id, raw)
        return _with_diag(port, do)
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_memory_peek(port: str = "", address: int = 0, length: int = 16) -> dict:
    """Read modem memory (hex string out). Peek reads bytes via DIAG_PEEKB_F.

    Memory access is restricted or disabled on most modern devices, and
    reads at bad addresses can crash some modems.
    """
    try:
        def do(d: DiagTransport):
            return d.memory_peek(address, length)
        return _with_diag(port, do)
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_memory_poke(port: str = "", address: int = 0, data: str = "",
                     dry_run: bool = True, confirm: bool = False) -> dict:
    """Write modem memory (DIAG_POKEB_F) (MODEM-WRITING; guarded).

    WARNING: poking modem memory can crash or permanently brick the
    device. Envelope layout is inferred, unverified on hardware.

    Refuses to open the serial port unless BOTH ``dry_run=False`` AND
    ``confirm=True`` are passed; with the defaults it returns a dry-run
    payload describing what it *would* write and touches nothing.

    `data` is a hex string.
    """
    would_do = {"port": port, "address": address, "data": data}
    if dry_run or not confirm:
        return {"dry_run": True, "executed": False, "would_do": would_do,
                "message": ("DRY RUN \u2014 nothing written; set dry_run=False "
                            "and confirm=True to proceed.")}
    try:
        raw = bytes.fromhex(data)
    except ValueError as exc:
        return {"error": "data must be a valid hex string: %s" % exc}
    try:
        def do(d: DiagTransport):
            return d.memory_poke(address, raw)
        return _with_diag(port, do)
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_efs_list(port: str = "", path: str = "/") -> dict:
    """List the entries of an EFS2 directory (e.g. \"/policyman\")."""
    try:
        def do(d: DiagTransport):
            d._efs_hello()
            return d.efs_list(path)
        return _with_diag(port, do)
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_efs_pull(port: str = "", remote_path: str = "",
                  local_path: str = "") -> dict:
    """Copy a modem EFS file to the host."""
    try:
        if not remote_path or not local_path:
            return {"error": "remote_path and local_path are required"}
        def do(d: DiagTransport):
            d._efs_hello()
            data = d.efs_read_file(remote_path)
            with open(local_path, "wb") as fh:
                fh.write(data)
            return {"remote_path": remote_path,
                    "local_path": local_path, "size": len(data)}
        return _with_diag(port, do)
    except OSError as exc:
        return {"error": "local file error: %s" % exc}
    except QcdmError as exc:
        return {"error": str(exc)}


def diag_efs_push(port: str = "", local_path: str = "",
                  remote_path: str = "", dry_run: bool = True,
                  confirm: bool = False) -> dict:
    """Push a host file into the modem EFS, then verify the read-back.

    WARNING: writing the wrong modem EFS file can stop the modem from
    booting or registering. Always pull/back up before pushing.

    Refuses to open the serial port unless BOTH ``dry_run=False`` AND
    ``confirm=True`` are passed; with the defaults it returns a dry-run
    payload describing what it *would* write and touches nothing.
    """
    would_do = {"port": port, "local_path": local_path,
                "remote_path": remote_path}
    if dry_run or not confirm:
        return {"dry_run": True, "executed": False, "would_do": would_do,
                "message": ("DRY RUN \u2014 nothing written; set dry_run=False "
                            "and confirm=True to proceed.")}
    try:
        if not remote_path or not local_path:
            return {"error": "local_path and remote_path are required"}
        with open(local_path, "rb") as fh:
            blob = fh.read()
        def do(d: DiagTransport):
            d._efs_hello()
            n = d.efs_write_file(remote_path, blob)
            verified = d.efs_read_file(remote_path) == blob
            return {"local_path": local_path, "remote_path": remote_path,
                    "written": n, "read_back_matches": verified}
        return _with_diag(port, do)
    except OSError as exc:
        return {"error": "local file error: %s" % exc}
    except QcdmError as exc:
        return {"error": str(exc)}


TOOLS = (
    diag_list_ports,
    diag_version,
    diag_nv_read,
    diag_nv_write,
    diag_memory_peek,
    diag_memory_poke,
    diag_efs_list,
    diag_efs_pull,
    diag_efs_push,
)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    if FastMCP is None:
        sys.stderr.write("mcp SDK not installed. Run `pip install -e .`.\n")
        sys.exit(1)

    mcp = FastMCP("qcdm-mcp")

    # Tools are defined at module level (so they are unit-testable) and
    # registered here with the FastMCP decorator factory.
    for tool in TOOLS:
        mcp.tool()(tool)

    mcp.run()


if __name__ == "__main__":
    main()