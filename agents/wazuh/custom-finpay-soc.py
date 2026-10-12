#!/var/ossec/framework/python/bin/python3
"""Wazuh -> FINPAY SOC integration.

Install on the Wazuh manager:
  cp custom-finpay-soc.py /var/ossec/integrations/custom-finpay-soc
  chown root:wazuh /var/ossec/integrations/custom-finpay-soc
  chmod 750 /var/ossec/integrations/custom-finpay-soc

ossec.conf:
  <integration>
    <name>custom-finpay-soc</name>
    <hook_url>https://soc.finpaytech.com/api/public/wazuh</hook_url>
    <api_key>soc_xxxxxxxx</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>

Then: systemctl restart wazuh-manager
Wazuh calls this script with: <alert_file> <api_key> <hook_url>
"""
import json
import sys
import urllib.request


def main():
    if len(sys.argv) < 4:
        sys.exit("usage: custom-finpay-soc <alert_file> <api_key> <hook_url>")
    alert_file, api_key, hook_url = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(alert_file) as f:
        alert = json.load(f)
    req = urllib.request.Request(
        hook_url,
        data=json.dumps(alert).encode(),
        method="POST",
        headers={"content-type": "application/json", "x-soc-key": api_key, "user-agent": "wazuh-finpay-soc/1.0"},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        r.read()


if __name__ == "__main__":
    main()
