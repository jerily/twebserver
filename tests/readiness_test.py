#!/usr/bin/env python3
"""Socket readiness/lifetime regressions; only the Python standard library is used.

Build the extension first, then run:
    python3 tests/readiness_test.py --tclsh /usr/local/bin/tclsh9.1 --libdir build

The runner starts a separate server per test on two ephemeral loopback ports.
CPU assertions use Linux /proc; other platforms still run the functional checks.
Pass a unittest test name to select one test, e.g. ReadinessTests.test_slow_http_reader.
"""

import argparse
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
TCLSH = shutil.which("tclsh9.1") or "tclsh"
LIBDIR = HERE.parent / "build"
LARGE_SIZE = 8 * 1024 * 1024


def unused_ports():
    # Reserve both at once to avoid choosing the same ephemeral port twice.
    with socket.socket() as first, socket.socket() as second:
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        return first.getsockname()[1], second.getsockname()[1]


def cpu_seconds(pid):
    stat = Path(f"/proc/{pid}/stat")
    if not stat.exists():
        return None
    # Fields after the parenthesized command start at field 3 (state).
    fields = stat.read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.pending_responses = {}
        self.http_port, self.tls_port = unused_ports()
        self.log = tempfile.TemporaryFile(mode="w+b")
        self.addCleanup(self.log.close)
        self.server = subprocess.Popen(
            [TCLSH, str(HERE / "readiness_server.tcl"), str(LIBDIR),
             str(self.http_port), str(self.tls_port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log,
        )
        self.addCleanup(self.stop_server)
        readable, _, _ = select.select([self.server.stdout], [], [], 5)
        self.assertTrue(readable, "server did not start within 5 seconds")
        self.assertEqual(self.server.stdout.readline().strip(), b"READY", self.server_log())

    def server_log(self):
        self.log.seek(0)
        return self.log.read().decode(errors="replace")[-8000:]

    def stop_server(self):
        try:
            self.server.communicate(b"stop\n", timeout=5)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.communicate()
            self.fail("server failed to shut down:\n" + self.server_log())
        self.assertEqual(self.server.returncode, 0, self.server_log())

    def connect(self, tls=False, raw=False, slow_reader=False):
        sock = socket.socket()
        self.addCleanup(sock.close)
        sock.settimeout(4)
        if slow_reader:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
        sock.connect(("127.0.0.1", self.tls_port if tls else self.http_port))
        if tls and not raw:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname="localhost")
            self.addCleanup(sock.close)
        return sock

    def assert_sleeping(self):
        # Permit accept/handshake/response setup before measuring a blocked wait.
        time.sleep(0.05)
        before = cpu_seconds(self.server.pid)
        time.sleep(0.4)
        after = cpu_seconds(self.server.pid)
        self.assertIsNone(self.server.poll(), self.server_log())
        if before is not None and after is not None:
            self.assertLess(after - before, 0.20,
                            "server used over half a CPU while awaiting socket readiness")

    def response(self, sock):
        data = bytearray(self.pending_responses.pop(sock, b""))
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(65536)
            self.assertTrue(chunk, "connection closed before response headers")
            data.extend(chunk)
        head, body = bytes(data).split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = int(lines[0].split()[1])
        headers = dict(line.split(b":", 1) for line in lines[1:])
        length = int(next(value for key, value in headers.items()
                          if key.lower() == b"content-length"))
        body = bytearray(body)
        deadline = time.monotonic() + 4
        while len(body) < length:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            chunk = sock.recv(min(65536, length - len(body)))
            self.assertTrue(chunk, f"connection closed after {len(body)} of {length} bytes")
            body.extend(chunk)
        if len(body) > length:
            self.pending_responses[sock] = bytes(body[length:])
        return status, bytes(body[:length])

    def assert_healthy(self, tls=False):
        with self.connect(tls=tls) as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(self.response(sock), (200, b"ok"))

    def fragmented_request(self, tls=False):
        with self.connect(tls=tls) as sock:
            # Initial idle accept must sleep, then resume solely on socket input.
            self.assert_sleeping()
            sock.sendall(b"POST /echo HTTP/1.1\r\nHost: local")
            self.assert_sleeping()
            sock.sendall(b"host\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\nabc")
            time.sleep(0.05)
            sock.sendall(b"def")
            self.assertEqual(self.response(sock), (200, b"abcdef"))

    def test_fragmented_http_sleeps_and_resumes(self):
        self.fragmented_request()

    def test_fragmented_tls_sleeps_and_resumes(self):
        self.fragmented_request(tls=True)

    def test_buffered_tls_request_spanning_records(self):
        # SSL_read may leave decrypted records buffered with no new fd edge.
        body = b"0123456789abcdef" * 4096
        headers = (b"POST /echo HTTP/1.1\r\nHost: localhost\r\n"
                   b"Content-Type: text/plain\r\nContent-Length: 65536\r\n\r\n")
        with self.connect(tls=True) as sock:
            sock.sendall(headers + body)
            self.assertEqual(self.response(sock), (200, body))

    def test_tls_keepalive_with_buffered_next_record(self):
        with self.connect(tls=True) as sock:
            # Each SSL write is a distinct record. On Linux, corking delivers
            # both records together, exercising OpenSSL's read-ahead buffer.
            cork = getattr(socket, "TCP_CORK", None)
            if cork is not None:
                sock.setsockopt(socket.IPPROTO_TCP, cork, 1)
            try:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
                sock.sendall(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                             b"Content-Type: text/plain\r\nContent-Length: 6\r\n\r\nsecond")
            finally:
                if cork is not None:
                    sock.setsockopt(socket.IPPROTO_TCP, cork, 0)
            self.assertEqual(self.response(sock), (200, b"ok"))
            self.assertEqual(self.response(sock), (200, b"second"))
            self.assertEqual(sock.recv(1), b"")

    def test_split_header_terminator(self):
        for split in (1, 2, 3):
            with self.subTest(split=split), self.connect() as sock:
                marker = b"\r\n\r\n"
                sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost" + marker[:split])
                time.sleep(0.05)
                sock.sendall(marker[split:])
                self.assertEqual(self.response(sock), (200, b"ok"))

    def test_http_read_deadline_without_other_requests(self):
        with self.connect() as sock:
            sock.sendall(b"POST /echo HTTP/1.1\r\nContent-Length: 6\r\n\r\na")
            self.assert_sleeping()
            # The read timer must run even though this socket receives no more input.
            self.assertEqual(self.response(sock)[0], 400)
        self.assert_healthy()

    def test_stalled_tls_handshake_sleeps_and_expires(self):
        with self.connect(tls=True, raw=True) as sock:
            self.assert_sleeping()
            self.assertEqual(sock.recv(1), b"", "unfinished TLS handshake did not expire")
        self.assert_healthy(tls=True)

    def test_keepalive_reuse_and_idle_expiry(self):
        for tls in (False, True):
            with self.subTest(tls=tls), self.connect(tls=tls) as sock:
                request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
                sock.sendall(request)
                self.assertEqual(self.response(sock), (200, b"ok"))
                time.sleep(0.05)
                sock.sendall(request[:5])
                time.sleep(0.05)
                sock.sendall(request[5:])
                self.assertEqual(self.response(sock), (200, b"ok"))
                self.assert_sleeping()
                sock.settimeout(4)
                self.assertEqual(sock.recv(1), b"", "idle keepalive connection did not expire")
            self.assert_healthy(tls=tls)

    def slow_reader(self, tls=False):
        with self.connect(tls=tls, slow_reader=True) as sock:
            sock.sendall(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
            # 8 MiB exceeds the send buffer; no other connection wakes this worker.
            self.assert_sleeping()
            self.assertEqual(self.response(sock), (200, b"x" * LARGE_SIZE))

    def test_slow_http_reader(self):
        self.slow_reader()

    def test_slow_tls_reader(self):
        self.slow_reader(tls=True)

    def test_timeout_during_nested_event_loop(self):
        # A handler can reenter Tcl's event loop while its connection expires.
        # Its resumed C callback must survive the deferred connection cleanup.
        with self.connect() as sock:
            sock.sendall(b"GET /nested HTTP/1.1\r\nHost: localhost\r\n\r\n")
            self.assertEqual(sock.recv(1), b"")
        time.sleep(0.7)
        self.assert_healthy()

    def test_disconnects_and_errors_do_not_leave_stale_events(self):
        for prefix in (b"", b"GE", b"invalid request\r\n\r\n") * 8:
            with self.connect() as sock:
                if prefix:
                    sock.sendall(prefix)
        for _ in range(8):
            with self.connect(tls=True, raw=True) as sock:
                sock.sendall(b"not a TLS record")
        # Reset during a blocked write, exercising queued writes and deferred frees.
        for tls in (False, True):
            with self.connect(tls=tls, slow_reader=True) as sock:
                sock.sendall(b"GET /large HTTP/1.1\r\nHost: localhost\r\n\r\n")
                time.sleep(0.05)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.assert_healthy()
        self.assert_healthy(tls=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tclsh", default=TCLSH, help="Tcl interpreter matching the built extension")
    parser.add_argument("--libdir", type=Path, default=LIBDIR, help="directory containing pkgIndex.tcl and the library")
    options, unittest_args = parser.parse_known_args()
    TCLSH = options.tclsh
    LIBDIR = options.libdir.resolve()
    if not Path("/proc/self/stat").exists():
        print("CPU assertions unavailable without Linux /proc; running functional checks.", file=sys.stderr)
    unittest.main(argv=[sys.argv[0], *unittest_args], verbosity=2)
