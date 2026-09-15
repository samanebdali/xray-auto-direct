import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "install" / "wgcf_to_shadow.py"

class ShadowGeneratorTests(unittest.TestCase):
    def test_generates_local_socks_and_wireguard(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            profile = d / "wgcf-profile.conf"
            output = d / "shadow.json"
            profile.write_text("""[Interface]
PrivateKey = private-test
Address = 172.16.0.2/32, 2606:4700:110:1/128
MTU = 1280

[Peer]
PublicKey = peer-test
Endpoint = engage.cloudflareclient.com:2408
Reserved = 0, 0, 0
""")
            subprocess.run([sys.executable, str(GEN), "--wgcf", str(profile), "--output", str(output)], check=True)
            cfg = json.loads(output.read_text())
            self.assertEqual(cfg["inbounds"][0]["listen"], "127.0.0.1")
            self.assertEqual(cfg["inbounds"][0]["port"], 20808)
            settings = cfg["outbounds"][0]["settings"]
            self.assertTrue(settings["noKernelTun"])
            self.assertEqual(settings["domainStrategy"], "ForceIPv4")
            self.assertEqual(settings["peers"][0]["reserved"], "AAAA")

if __name__ == "__main__":
    unittest.main()
