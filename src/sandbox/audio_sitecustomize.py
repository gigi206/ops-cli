# ops audio shim for the Python voice stack, staged on PYTHONPATH under `audio = true`.
#
# It patches two ecosystem quirks a hermetic, MITM-proxied cage exposes. Both are additive/conditional
# and generic (any ctypes / any certifi consumer benefits), and it is embedded verbatim into the ops
# binary (`include_str!`) — no interpolation, so it is safe to stage as-is.
#
# A `sitecustomize` on PYTHONPATH shadows one an app might ship (Python imports only the first on
# sys.path); accepted trade-off, since it is staged only under the opt-in, trusted `audio = true`.

import os
import glob
import ctypes.util

# (1) Resolve native libraries from LD_LIBRARY_PATH.
# A hermetic cage has no ldconfig/gcc/ld, so the stock ctypes.util.find_library (which shells out to
# one of those) returns None — breaking any package that loads a native library by name, notably
# sounddevice, which resolves PortAudio via find_library("portaudio"). Scan LD_LIBRARY_PATH as a last
# resort; the returned full path is then dlopen'ed directly. Additive: the stock lookup wins when it
# succeeds.
_ops_orig_find_library = ctypes.util.find_library


def _ops_find_library(name):
    found = _ops_orig_find_library(name)
    if found:
        return found
    for directory in os.environ.get("LD_LIBRARY_PATH", "").split(os.pathsep):
        if not directory:
            continue
        for pattern in ("lib%s.so.*" % name, "lib%s.so" % name, "%s.so.*" % name, "%s.so" % name):
            hits = sorted(glob.glob(os.path.join(directory, pattern)))
            if hits:
                return hits[-1]
    return found


ctypes.util.find_library = _ops_find_library

# (2) Make certifi honor SSL_CERT_FILE.
# A certifi-pinned TLS client (edge-tts's read-aloud) verifies against certifi's Mozilla bundle
# (ssl.create_default_context(cafile=certifi.where())) and ignores SSL_CERT_FILE. Under the egress
# allowlist the cage's only egress is ops's TLS-terminating proxy with a per-session MITM CA, which
# certifi does not know -> CERTIFICATE_VERIFY_FAILED and read-aloud fails. ops already sets
# SSL_CERT_FILE to that CA (the same one curl/requests/nix trust); make certifi.where() return it so a
# certifi-pinned tool trusts the same CA as every other client. Only when SSL_CERT_FILE is set (i.e.
# under the MITM proxy); left alone otherwise, so direct TLS keeps the real Mozilla roots.
# Best-effort: no certifi installed -> no-op.
_ops_ca = os.environ.get("SSL_CERT_FILE")
if _ops_ca and os.path.exists(_ops_ca):
    try:
        import certifi

        certifi.where = lambda: _ops_ca
        try:
            import certifi.core

            certifi.core.where = lambda: _ops_ca
        except Exception:
            pass
    except Exception:
        pass
