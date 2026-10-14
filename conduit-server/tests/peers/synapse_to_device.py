#!/usr/bin/env python3
"""Required live-peer assertions; any missing prerequisite or failure is fatal.

Run with a venv containing requirements.txt, after cargo build -p conduit-server.
Both peers use loopback TLS proxies and trust only a generated test CA for the
private federation. Conduit uses an isolated PostgreSQL DB; Synapse uses SQLite.
"""

import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def forward(self):
        if self.server.target is None:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"errcode":"M_UNKNOWN","error":"temporarily unavailable"}')
            return
        connection = http.client.HTTPConnection("127.0.0.1", timeout=10)
        try:
            if isinstance(self.server.target, Path):
                connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.sock.settimeout(10)
                connection.sock.connect(str(self.server.target))
            else:
                connection = http.client.HTTPConnection(*self.server.target, timeout=10)
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = {key: value for key, value in self.headers.items()
                       if key.lower() not in ("connection", "transfer-encoding", "accept-encoding")}
            headers["Connection"] = "close"
            headers["X-Forwarded-For"] = self.client_address[0]
            headers["X-Forwarded-Proto"] = "https"
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            body = response.read()
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in ("connection", "transfer-encoding", "content-length"):
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            connection.close()

    do_GET = do_POST = do_PUT = forward


def checked(command, **kwargs):
    return subprocess.run(command, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs)


def certificates(root):
    ca = root / "ca.pem"
    (root / "ca.cnf").write_text("""[req]
distinguished_name=dn
prompt=no
x509_extensions=extensions
[dn]
CN=Conduit integration CA
[extensions]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
""")
    checked(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "ca.key"), "-out", str(ca), "-days", "1",
             "-config", str(root / "ca.cnf")])
    checked(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(root / "server.key"), "-out", str(root / "server.csr"),
             "-subj", "/CN=localhost"])
    (root / "extensions.cnf").write_text("""basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
""")
    checked(["openssl", "x509", "-req", "-in", str(root / "server.csr"),
             "-CA", str(ca), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
             "-out", str(root / "server.pem"), "-days", "1", "-extfile",
             str(root / "extensions.cnf")])
    return ca


def proxy(root, target, stack):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    server.daemon_threads = True
    server.target = target
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "server.pem", root / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return server, f"127.0.0.1:{server.server_port}"


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def spawn(command, log, stack, **kwargs):
    output = stack.enter_context(log.open("wb"))
    process = subprocess.Popen(command, stdout=output, stderr=output,
                               stdin=subprocess.DEVNULL, **kwargs)
    stack.callback(stop, process)
    return process


def wait_for(check, processes, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for process, log in processes:
            if process.poll() is not None:
                raise AssertionError(f"peer exited {process.returncode}: {log.read_text()}")
        try:
            result = check()
            if result:
                return result
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise AssertionError("peer readiness/delivery deadline expired")


def main(pdu_wire=False):
    # Importing the installed peer is a prerequisite check, never a skip.
    import synapse
    import importlib.metadata
    assert importlib.metadata.version("matrix-synapse") == "1.162.0"
    repo = Path(__file__).resolve().parents[3]
    binary = Path(os.environ.get("CONDUIT_TEST_BINARY", repo / "target/debug/conduit-server")).resolve()
    assert binary.is_file(), "build conduit-server first"
    admin = os.environ.get("DATABASE_URL", "postgresql://postgres@localhost/postgres")
    database = f"conduit_test_peer_{uuid.uuid4().hex}"
    parsed = urllib.parse.urlsplit(admin)
    database_url = urllib.parse.urlunsplit(parsed._replace(path=f"/{database}"))
    with tempfile.TemporaryDirectory(prefix="cdpeer-", dir="/tmp") as directory, contextlib.ExitStack() as stack:
        root = Path(directory)
        checked(["psql", "--no-psqlrc", admin, "-v", "ON_ERROR_STOP=1", "-c", f"CREATE DATABASE {database}"])
        stack.callback(checked, ["psql", "--no-psqlrc", admin, "-v", "ON_ERROR_STOP=1", "-c", f"DROP DATABASE {database} WITH (FORCE)"])
        ca = certificates(root)
        context = ssl.create_default_context(cafile=ca)
        conduit_proxy, conduit_name = proxy(root, ("127.0.0.1", 1), stack)
        synapse_proxy, synapse_name = proxy(root, root / "synapse.sock", stack)
        bases = {"conduit": f"https://{conduit_name}", "synapse": f"https://{synapse_name}"}

        def request(peer, method, path, token=None, body=None, status=200, extra_headers=None):
            headers = {"Content-Type": "application/json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            headers.update(extra_headers or {})
            payload = None if body is None else json.dumps(body).encode()
            req = urllib.request.Request(bases[peer] + path, data=payload, headers=headers, method=method)
            try:
                response = urllib.request.urlopen(req, context=context, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                if response.status != status:
                    for log in root.glob("*.log"):
                        print("\n".join(log.read_text().splitlines()[-100:]), file=sys.stderr)
                assert response.status == status, f"{peer} {method} {path}: HTTP {response.status}: {data!r}"
                return json.loads(data) if data.startswith(b"{") else data.decode()

        synapse_config = {
            "server_name": synapse_name,
            "report_stats": False,
            "listeners": [{"type": "http", "path": str(root / "synapse.sock"), "tls": False, "x_forwarded": True,
                           "resources": [{"names": ["client", "federation"], "compress": False}]}],
            "database": {"name": "sqlite3", "args": {"database": str(root / "synapse.db")}},
            "signing_key_path": str(root / "synapse.signing.key"),
            "media_store_path": str(root / "synapse-media"),
            "enable_registration": True, "enable_registration_without_verification": True,
            "federation_verify_certificates": True, "federation_custom_ca_list": [str(ca)],
            "ip_range_blacklist": [], "ip_range_whitelist": ["127.0.0.1/32"], "trusted_key_servers": [],
            "macaroon_secret_key": uuid.uuid4().hex,
        }
        config = root / "synapse.yaml"
        config.write_text(json.dumps(synapse_config))
        synapse_log = root / "synapse.log"
        synapse_process = spawn([sys.executable, "-m", "synapse.app.homeserver", "--config-path", str(config)], synapse_log, stack, cwd=root)
        wait_for(lambda: (root / "synapse.sock").exists(), [(synapse_process, synapse_log)])
        wait_for(lambda: request("synapse", "GET", "/health") == "OK", [(synapse_process, synapse_log)])
        print("Synapse ready with verified loopback TLS", flush=True)

        ready = root / "conduit-ready.json"
        env = dict(os.environ, DATABASE_URL=database_url, CONDUIT_SERVER_NAME=conduit_name,
                   CONDUIT_LISTEN_ADDR="127.0.0.1:0", CONDUIT_READY_FILE=str(ready),
                   CONDUIT_OIDC_ISSUER="off", CONDUIT_FEDERATION="1", CONDUIT_TLS_CA=str(ca),
                   CONDUIT_MEDIA_ROOT=str(root / "conduit-media"), CONDUIT_AS_REGISTRATIONS_DIR=str(root / "app-services"))
        env.pop("CONDUIT_REMOTE_KEYS_OVERRIDE", None)
        conduit_log = root / "conduit.log"

        def start_conduit():
            ready.unlink(missing_ok=True)
            process = spawn([str(binary)], conduit_log, stack, cwd=root, env=env)
            value = wait_for(lambda: json.loads(ready.read_text()) if ready.exists() else None, [(process, conduit_log)])
            host, port = value["address"].rsplit(":", 1)
            conduit_proxy.target = (host, int(port))
            wait_for(lambda: request("conduit", "GET", "/health") == "ok", [(process, conduit_log)])
            return process

        conduit_process = start_conduit()

        def register(peer, name):
            challenge = request(peer, "POST", "/_matrix/client/v3/register", body={"username": name, "password": "test-password"}, status=401)
            return request(peer, "POST", "/_matrix/client/v3/register", body={"username": name,
                "password": "test-password", "auth": {"type": "m.login.dummy", "session": challenge["session"]}})

        alice = register("conduit", "alice")
        bob = register("synapse", "bob")
        tokens = {"conduit": alice["access_token"], "synapse": bob["access_token"]}

        cursors = {peer: request(peer, "GET", "/_matrix/client/v3/sync", token)["next_batch"]
                   for peer, token in tokens.items()}

        def send(peer, target, transaction, text):
            path = f"/_matrix/client/v3/sendToDevice/m.test/{transaction}"
            return request(peer, "PUT", path, tokens[peer], {"messages": {target["user_id"]: {"*": {"body": text}}}})

        def receive(peer, expected_sender, text):
            def check():
                path = "/_matrix/client/v3/sync?timeout=1000&since=" + urllib.parse.quote(cursors[peer], safe="")
                response = request(peer, "GET", path, tokens[peer])
                cursors[peer] = response["next_batch"]
                events = response.get("to_device", {}).get("events", [])
                if not events:
                    return None
                assert events == [{"sender": expected_sender, "type": "m.test", "content": {"body": text}}], events
                acknowledged = request(peer, "GET", "/_matrix/client/v3/sync?since=" + urllib.parse.quote(response["next_batch"], safe=""), tokens[peer])
                assert acknowledged.get("to_device", {}).get("events", []) == [], acknowledged
                cursors[peer] = acknowledged["next_batch"]
                return True
            try:
                wait_for(check, [(conduit_process, conduit_log), (synapse_process, synapse_log)], timeout=20)
            except Exception:
                print(conduit_log.read_text(), file=sys.stderr)
                print(synapse_log.read_text(), file=sys.stderr)
                raise

        send("conduit", bob, "forward", "Hello, 世界")
        receive("synapse", alice["user_id"], "Hello, 世界")
        send("synapse", alice, "reverse", "Reply from Synapse")
        receive("conduit", bob["user_id"], "Reply from Synapse")
        print("Bidirectional m.direct_to_device delivery passed", flush=True)
        stop(conduit_process)
        conduit_process = start_conduit()
        send("conduit", bob, "forward", "Changed retry")
        time.sleep(0.5)
        assert request("synapse", "GET", "/_matrix/client/v3/sync?since=" + urllib.parse.quote(cursors["synapse"], safe=""), tokens["synapse"]).get("to_device", {}).get("events", []) == []
        print("Conduit restart/retry deduplication passed", flush=True)
        target = synapse_proxy.target
        synapse_proxy.target = None
        send("conduit", bob, "recover", "Pending across crash")
        stop(conduit_process)
        synapse_proxy.target = target
        conduit_process = start_conduit()
        receive("synapse", alice["user_id"], "Pending across crash")
        print("Durable outbound queue recovery passed", flush=True)

        # Signedjson is the peer's independent signing implementation. Exercise
        # EDU ID replay across transactions, Unicode bounds, and origin spoofing.
        from signedjson.key import read_signing_keys
        from signedjson.sign import sign_json
        with (root / "synapse.signing.key").open() as key_file:
            signing_key = read_signing_keys(key_file)[0]

        def raw_transaction(transaction, body, status=200):
            path = f"/_matrix/federation/v1/send/{transaction}"
            signed = sign_json({"method": "PUT", "uri": path, "origin": synapse_name,
                                "destination": conduit_name, "content": body}, synapse_name, signing_key)
            key_id, signature = next(iter(signed["signatures"][synapse_name].items()))
            auth = f'X-Matrix origin="{synapse_name}",destination="{conduit_name}",key="{key_id}",sig="{signature}"'
            return request("conduit", "PUT", path, body=body, status=status, extra_headers={"Authorization": auth})

        def edu(message_id, text):
            return {"edu_type": "m.direct_to_device", "content": {"sender": bob["user_id"],
                "type": "m.test", "message_id": message_id, "messages": {alice["user_id"]: {"*": {"body": text}}}}}

        def transaction_body(edus):
            return {"origin": synapse_name, "origin_server_ts": int(time.time() * 1000), "pdus": [], "edus": edus}

        def raw_edu(transaction, message_id, sender, text):
            message = edu(message_id, text)
            message["content"]["sender"] = sender
            return raw_transaction(transaction, transaction_body([message]))

        raw_edu("raw-1", "😀" * 32, bob["user_id"], "Unicode ID")
        receive("conduit", bob["user_id"], "Unicode ID")
        stop(conduit_process)
        conduit_process = start_conduit()
        raw_edu("raw-2", "😀" * 32, bob["user_id"], "Duplicate after restart")
        raw_edu("raw-3", "😀" * 33, bob["user_id"], "Invalid ID length")
        raw_edu("raw-4", "spoof", "@forged:other.test", "Forged sender")
        assert request("conduit", "GET", "/_matrix/client/v3/sync?since=" + urllib.parse.quote(cursors["conduit"], safe=""), tokens["conduit"]).get("to_device", {}).get("events", []) == []
        raw_edu("raw-5", "spoof", bob["user_id"], "Valid sender after rejected spoof")
        receive("conduit", bob["user_id"], "Valid sender after rejected spoof")
        print("Independent signature, EDU replay, Unicode length and origin assertions passed", flush=True)

        original = raw_edu("frozen", "frozen-1", bob["user_id"], "Frozen request")
        receive("conduit", bob["user_id"], "Frozen request")
        stop(conduit_process)
        conduit_process = start_conduit()
        assert raw_edu("frozen", "frozen-2", bob["user_id"], "Changed HTTP transaction") == original
        assert request("conduit", "GET", "/_matrix/client/v3/sync?since=" + urllib.parse.quote(cursors["conduit"], safe=""), tokens["conduit"]).get("to_device", {}).get("events", []) == []

        checked(["psql", "--no-psqlrc", database_url, "-v", "ON_ERROR_STOP=1", "-c", """
            CREATE FUNCTION fail_second_delivery() RETURNS trigger AS $$
            BEGIN
                IF NEW.content->>'body' = 'Second original' THEN RAISE EXCEPTION 'injected delivery failure'; END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            CREATE TRIGGER fail_second_delivery BEFORE INSERT ON to_device_queue
                FOR EACH ROW EXECUTE FUNCTION fail_second_delivery();
        """])
        body = transaction_body([edu("partial-1", "First original"), edu("partial-2", "Second original")])
        raw_transaction("partial", body, status=500)
        receive("conduit", bob["user_id"], "First original")
        stop(conduit_process)
        checked(["psql", "--no-psqlrc", database_url, "-v", "ON_ERROR_STOP=1", "-c", "DROP TRIGGER fail_second_delivery ON to_device_queue"])
        conduit_process = start_conduit()
        raw_transaction("partial", transaction_body([edu("replacement", "Unwanted replacement")]))
        receive("conduit", bob["user_id"], "Second original")
        print("Whole HTTP transaction replay and interrupted original-body recovery passed", flush=True)

        for transaction, body in [
            ("too-many-edus", transaction_body([{"edu_type": "unknown", "content": {}}] * 101)),
            ("too-many-pdus", dict(transaction_body([]), pdus=[{}] * 51)),
            ("missing-time", {"origin": synapse_name, "pdus": []}),
            ("wrong-origin", dict(transaction_body([]), origin="forged.test")),
        ]:
            raw_transaction(transaction, body, status=400)
        raw_transaction("maximum-edus", transaction_body([{"edu_type": "unknown", "content": {}}] * 100))
        large = dict(transaction_body([]), pdus=[{"unknown": "x" * 60_000}] * 50)
        result = raw_transaction("large-frame", large)
        assert len(result["pdus"]) == 50
        print("Federation required fields, count limits and >2MB frame assertions passed", flush=True)

        if pdu_wire:
            from synapse.api.room_versions import RoomVersions
            from synapse.crypto.event_signing import add_hashes_and_signatures
            from synapse.events import make_event_from_dict
            wire = {"auth_events": [], "prev_events": [], "depth": 1,
                "room_id": f"!wire:{synapse_name}", "sender": bob["user_id"],
                "type": "m.room.create", "state_key": "", "content": {"room_version": "11"},
                "origin_server_ts": int(time.time() * 1000),
                "org.conduit.test": {"opaque": "preserve me", "unicode": "世界"}}
            add_hashes_and_signatures(RoomVersions.V11, wire, synapse_name, signing_key)
            event_id = make_event_from_dict(wire, RoomVersions.V11).event_id
            assert "event_id" not in wire
            result = raw_transaction("wire-create", dict(transaction_body([]), pdus=[wire]))
            assert result["pdus"].get(event_id) == {}, result
            stop(conduit_process)
            conduit_process = start_conduit()
            event_path = "/_matrix/federation/v1/event/" + urllib.parse.quote(event_id, safe="")
            signed = sign_json({"method": "GET", "uri": event_path, "origin": synapse_name,
                "destination": conduit_name}, synapse_name, signing_key)
            key_id, signature = next(iter(signed["signatures"][synapse_name].items()))
            auth = f'X-Matrix origin="{synapse_name}",destination="{conduit_name}",key="{key_id}",sig="{signature}"'
            stored = request("conduit", "GET", event_path, extra_headers={"Authorization": auth})["pdus"][0]
            assert "event_id" not in stored, stored
            assert stored["org.conduit.test"] == wire["org.conduit.test"]
            assert make_event_from_dict(stored, RoomVersions.V11).event_id == event_id
            print("Independent v11 PDU signing/reference ID, no-ID wire and extension persistence passed", flush=True)


if __name__ == "__main__":
    main()
