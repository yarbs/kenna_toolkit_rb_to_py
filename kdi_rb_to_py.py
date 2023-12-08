import json
import csv
from datetime import datetime

class KennaToolkit:
    def __init__(self):
        self.assets = []
        self.vuln_defs = []
        self.paged_assets = []
        self.uploaded_files = []

    def uniq(self, asset):
        return {
            "file": asset.get("file"),
            "ip_address": asset.get("ip_address"),
            "mac_address": asset.get("mac_address"),
            "hostname": asset.get("hostname"),
            "ec2": asset.get("ec2"),
            "netbios": asset.get("netbios"),
            "url": asset.get("url"),
            "fqdn": asset.get("fqdn"),
            "external_id": asset.get("external_id"),
            "database": asset.get("database"),
            "application": asset.get("application"),
            "image": asset.get("image_id"),
            "container": asset.get("container_id")
        }

    def kdi_initialize(self):
        self.assets = []
        self.vuln_defs = []
        self.paged_assets = []
        self.uploaded_files = []

    def create_kdi_asset(self, asset_hash, dup_check=True):
        self.kdi_initialize()

        uniq_asset_hash = self.uniq(asset_hash)
        if dup_check and any(uniq(a) == uniq_asset_hash for a in self.assets):
            return None

        asset_hash["tags"] = asset_hash.get("tags", [])
        asset_hash["vulns"] = []

        self.assets.append({k: v for k, v in asset_hash.items() if v is not None})
        return {k: v for k, v in asset_hash.items() if v is not None}

    def find_or_create_kdi_asset(self, asset_hash, match_key=None):
        self.kdi_initialize()
        uniq_asset_hash = self.uniq(asset_hash)
        asset_hash_key = asset_hash.get(match_key) if match_key else None

        a = next((asset for asset in self.assets if asset.get(match_key) == asset_hash_key), None) if match_key else None
        if not a:
            print("Unable to find asset {}, creating a new one...".format(asset_hash))
            self.create_kdi_asset(asset_hash, False)
            a = next((asset for asset in self.assets if asset.get(match_key) == asset_hash_key), None) if match_key else None

        return a

    def create_kdi_asset_vuln(self, asset_hash, vuln_hash, match_key=None):
        self.kdi_initialize()

        a = self.find_or_create_kdi_asset(asset_hash, match_key)

        vuln_hash["status"] = vuln_hash.get("status", "open")
        vuln_hash["port"] = int(vuln_hash.get("port", 0)) if vuln_hash.get("port") else None

        now = datetime.utcnow().strftime("%Y-%m-%d")
        vuln_hash["last_seen_at"] = vuln_hash.get("last_seen_at", now)
        vuln_hash["created_at"] = vuln_hash.get("created_at", now)

        a["vulns"] = a.get("vulns", [])
        a["vulns"].append({k: v for k, v in vuln_hash.items() if v is not None})

        return {k: v for k, v in vuln_hash.items() if v is not None}

    def create_kdi_asset_finding(self, asset_hash, finding_hash, match_key=None):
        self.kdi_initialize()

        a = self.find_or_create_kdi_asset(asset_hash, match_key)

        finding_hash["triage_state"] = finding_hash.get("triage_state", "new")
        finding_hash["last_seen_at"] = finding_hash.get("last_seen_at", datetime.utcnow().strftime("%Y-%m-%d"))

        a["findings"] = a.get("findings", [])
        a["findings"].append({k: v for k, v in finding_hash.items() if v is not None})

        return {k: v for k, v in finding_hash.items() if v is not None}

    def create_paged_kdi_asset_vuln(self, asset_hash, vuln_hash, match_key=None):
        self.kdi_initialize()

        uniq_asset_hash = self.uniq(asset_hash)
        asset_hash_key = asset_hash.get(match_key) if match_key else None

        a = next((asset for asset in self.paged_assets if asset.get(match_key) == asset_hash_key), None) if match_key else None
        if not a:
            a = next((asset for asset in self.assets if asset.get(match_key) == asset_hash_key), None) if match_key else None
            if a:
                self.paged_assets.append(a)
                self.assets.remove(a)
            else:
                a = asset_hash
                self.paged_assets.append(a)

        vuln_hash["status"] = vuln_hash.get("status", "open")
        vuln_hash["port"] = int(vuln_hash.get("port", 0)) if vuln_hash.get("port") else None
        vuln_hash["last_seen_at"] = vuln_hash.get("last_seen_at", datetime.utcnow().strftime("%Y-%m-%d"))

        a["vulns"] = a.get("vulns", [])
        a["vulns"].append({k: v for k, v in vuln_hash.items() if v is not None})

        return True

    def kdi_upload(self, output_dir, filename, kenna_connector_id, kenna_api_host, kenna_api_key, skip_autoclose=False, max_retries=3, version=1):
        write_assets = self.paged_assets if self.paged_assets and any(self.paged_assets) else self.assets
        if not write_assets:
            return

        self.write_file_stream(output_dir, filename, skip_autoclose, write_assets, self.vuln_defs, version)
        print("Output is available at: {}/{}".format(output_dir, filename))

        if kenna_connector_id and kenna_api_host and kenna_api_key:
            print("Attempting to upload to Kenna API at {}".format(kenna_api_host))
            response_json = self.upload_file_to_kenna_connector(kenna_connector_id, kenna_api_host, kenna_api_key, "{}/{}".format(output_dir, filename), False, max_retries)
            filenum = response_json.get("data_file")
            self.uploaded_files = [] if self.uploaded_files is None else self.uploaded_files
            self.uploaded_files.append(filenum)

        self.clear_data_arrays()
        return response_json

    def kdi_connector_kickoff(self, kenna_connector_id, kenna_api_host, kenna_api_key):
        if not self.uploaded_files:
            return

        print("Attempting to run Kenna Connector at {}".format(kenna_api_host))
        self.run_files_on_kenna_connector(kenna_connector_id, kenna_api_host, kenna_api_key, self.uploaded_files)

    def clear_data_arrays(self):
        self.assets = [] if self.paged_assets is None or not any(self.paged_assets) else self.paged_assets
        self.paged_assets = []
        self
