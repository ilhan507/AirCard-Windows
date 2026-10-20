# AirCard-Windows Patch: iOS 27 Card Scanning (os_trace_relay)

## Problem
iOS 27 no longer exposes pass paths / passIDs via com.apple.syslog_relay,
breaking card detection on iOS 27.0.x devices.

## Fix
scan_syslog_for_cards (src/scanner.rs) now starts com.apple.os_trace_relay and
speaks the unified-logging stream protocol:
- StartActivity request (binary plist): Pid=0xFFFFFFFF, MessageFilter=0xFFFF,
  StreamFlags=0x3C; reply Status must be "RequestSuccessful"
- 5-byte frames: type 1 = plist (big-endian length), type 2 = activity record
  (little-endian length); max frame 16 MiB
- 129-byte activity record header (offsets 0=type, 5=header_len, 37=process_len,
  107=image_len, 109=message_len), NUL-terminated process/image/message strings
- Multi-line messages preserved (pass paths appear on continuation lines)

New module src/os_trace.rs implements framing + parsing + 7 unit tests.
Stop button stays responsive (SO_RCVTIMEO on non-TLS sockets + stop_flag polling).
GUI, flashing and AirTraffic handshake are untouched; the scanner function
signature is unchanged.

## Build & Test
cargo build --release -> target/release/aircard.exe
cargo test            -> os_trace unit tests + existing engine/scanner tests
Target: iOS 27.0.x devices paired over USB.
