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

"""Unit tests for qcdm-mcp (no hardware)."""

import inspect
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import qcdm_mcp_server as qcdm
from qcdm_mcp_server import (
    fcs16,
    hdlc_encode,
    hdlc_decode,
    HDLC_TRAILER,
    HDLC_ESCAPE,
)


DRY_RUN_MESSAGE = (
    "DRY RUN \u2014 nothing written; set dry_run=False and confirm=True "
    "to proceed."
)


# --- HDLC framing tests ---
def test_hdlc_encode_decode_roundtrip():
    payload = b"\x00\x01\x02\x03test\xff"
    encoded = hdlc_encode(payload)
    # Ensure trailer present
    assert encoded.endswith(bytes([HDLC_TRAILER]))
    dec = hdlc_decode(encoded)
    # dec is unescaped frame content including trailer; should end with trailer
    assert dec.endswith(bytes([HDLC_TRAILER]))
    # payload + crc (2 bytes) + trailer
    assert dec[:-3] == payload
    # check CRC
    crc = (dec[-3]) | (dec[-2] << 8)
    assert fcs16(payload) == crc


def test_hdlc_escape_sequence():
    # Payload containing trailer and escape
    payload = bytes([HDLC_TRAILER, HDLC_ESCAPE, 0xAA])
    encoded = hdlc_encode(payload)
    # Should contain escape sequences
    assert b"\x7d\x5e" in encoded  # trailer escaped
    assert b"\x7d\x5d" in encoded  # escape escaped
    dec = hdlc_decode(encoded)
    assert dec[:-3] == payload


def test_diag_packet_roundtrip():
    # DIAG packet is just cmd byte + body; framing wraps it
    cmd = 0x26  # DIAG_NV_READ_F
    body = b"\x01\x00"  # item_id = 1
    packet = bytes([cmd]) + body
    encoded = hdlc_encode(packet)
    dec = hdlc_decode(encoded)
    assert dec[:-3] == packet  # payload + crc + trailer
    crc = dec[-3] | (dec[-2] << 8)
    assert fcs16(packet) == crc


# --- CRC tests ---
def test_crc16_x25_known():
    # Common test vectors for CRC-16/X-25 (poly 0x8408, reflected)
    data = b"123456789"
    assert fcs16(data) == 0x906E
    # Empty input: init 0xFFFF, no updates, final complement -> (~0xFFFF) & 0xFFFF = 0
    assert fcs16(b"") == 0


# --- Guardrail tests: writing tools must not touch the serial port by default ---
@pytest.fixture
def no_serial(monkeypatch):
    """Make any attempt to open a serial transport/port explode."""

    def _boom(*args, **kwargs):
        raise AssertionError("serial port was opened during a dry run!")

    monkeypatch.setattr(qcdm, "_open", _boom)
    monkeypatch.setattr(qcdm, "DiagTransport", _boom)
    return _boom


def test_diag_nv_write_guard_defaults(no_serial):
    result = qcdm.diag_nv_write(item_id=550, data="01ff")
    assert result["executed"] is False
    assert result["dry_run"] is True
    assert result["would_do"] == {"port": "", "item_id": 550, "data": "01ff"}
    assert result["message"] == DRY_RUN_MESSAGE


def test_diag_memory_poke_guard_defaults(no_serial):
    result = qcdm.diag_memory_poke(address=0x1000, data="deadbeef")
    assert result["executed"] is False
    assert result["dry_run"] is True
    assert result["would_do"] == {
        "port": "", "address": 0x1000, "data": "deadbeef"}
    assert result["message"] == DRY_RUN_MESSAGE


def test_diag_efs_push_guard_defaults(no_serial):
    result = qcdm.diag_efs_push(local_path="local.bin", remote_path="/nv/x")
    assert result["executed"] is False
    assert result["dry_run"] is True
    assert result["would_do"] == {
        "port": "", "local_path": "local.bin", "remote_path": "/nv/x"}
    assert result["message"] == DRY_RUN_MESSAGE


def test_partial_flags_still_guard(no_serial):
    # dry_run=False alone must still guard
    r1 = qcdm.diag_nv_write(item_id=1, data="00", dry_run=False, confirm=False)
    assert r1["executed"] is False and r1["dry_run"] is True
    # confirm=True alone must still guard
    r2 = qcdm.diag_nv_write(item_id=1, data="00", dry_run=True, confirm=True)
    assert r2["executed"] is False and r2["dry_run"] is True


def test_guarded_tools_are_the_writing_ones():
    guarded = {"diag_nv_write", "diag_memory_poke", "diag_efs_push"}
    unguarded = {"diag_version", "diag_nv_read", "diag_memory_peek",
                 "diag_efs_list", "diag_efs_pull", "diag_list_ports"}
    for name in guarded:
        params = inspect.signature(getattr(qcdm, name)).parameters
        assert params["dry_run"].default is True, name
        assert params["confirm"].default is False, name
    for name in unguarded:
        params = inspect.signature(getattr(qcdm, name)).parameters
        assert "dry_run" not in params, name
        assert "confirm" not in params, name