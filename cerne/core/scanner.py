import requests
import math
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_vulnerabilities(packages_dict, ecosystem="Go", on_progress=None):
    """
    Returns {pkg_name: [DICT_OSV_LIST]}
    """
    logging.info(f"Starting scan of {len(packages_dict)} packages...")

    url = "https://api.osv.dev/v1/querybatch"
    batch_size = 200

    osv_ecosystem = ecosystem
    if ecosystem == "Go Modules": osv_ecosystem = "Go"
    if ecosystem == "RubyGems": osv_ecosystem = "RubyGems"
    if ecosystem == "NPM": osv_ecosystem = "npm"
    if ecosystem == "PyPI (Pip)": osv_ecosystem = "PyPI"

    all_queries = []
    all_pkg_names = []

    for name, ver in packages_dict.items():
        all_queries.append({
            "package": {"name": name, "ecosystem": osv_ecosystem},
            "version": ver
        })
        all_pkg_names.append(name)

    total_pkgs = len(all_queries)
    if total_pkgs == 0:
        return {}

    vuln_map = {}
    num_batches = math.ceil(total_pkgs / batch_size)

    batches_data = []
    for i in range(num_batches):
        start = i * batch_size
        end = start + batch_size
        batches_data.append((all_queries[start:end], all_pkg_names[start:end]))

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_batch = {
            executor.submit(process_batch, url, b_q, b_n): i
            for i, (b_q, b_n) in enumerate(batches_data)
        }

        processed_count = 0
        for future in as_completed(future_to_batch):
            try:
                local_map = future.result()
                vuln_map.update(local_map)
                processed_count += 1
                if on_progress:
                    on_progress(processed_count, num_batches)
            except Exception as e:
                logging.error(f"Thread error: {e}")

    return vuln_map


def process_batch(url, queries, names):
    local_map = {}
    try:
        response = requests.post(url, json={"queries": queries}, timeout=15)
        if response.status_code == 200:
            results = response.json().get("results", [])
            for idx, res in enumerate(results):
                vulns = res.get("vulns", [])
                if vulns:
                    pkg_name = names[idx]
                    local_map[pkg_name] = vulns
    except Exception as e:
        logging.error(f"HTTP Error: {e}")
        raise e
    return local_map


def enrich_tree(node, vuln_map):
    if node.name in vuln_map:
        node.vulnerable = True
        node.vuln_details = vuln_map[node.name]

        count = len(node.vuln_details)
        first_id = node.vuln_details[0].get("id", "Unknown")
        node.vuln_summary = f"{count} vulns (e.g. {first_id})"

    for child in node.children:
        enrich_tree(child, vuln_map)
