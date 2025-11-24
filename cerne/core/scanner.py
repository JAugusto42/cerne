import requests
import math
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_vulnerabilities(packages_dict, ecosystem="Go", on_progress=None):
    """
    Scans packages in batches using threads (No persistence cache for stability).
    Returns: {pkg_name: [list_of_full_vuln_details]}
    """
    logging.info(f"Scanning {len(packages_dict)} packages...")

    url = "https://api.osv.dev/v1/querybatch"
    # Aumentei um pouco o batch pois sem cache de disco, a rede aguenta mais
    BATCH_SIZE = 250

    osv_ecosystem = ecosystem
    if ecosystem == "Go Modules": osv_ecosystem = "Go"
    if ecosystem == "RubyGems": osv_ecosystem = "RubyGems"
    if ecosystem in ["NPM", "NPM/Yarn"]: osv_ecosystem = "npm"
    if ecosystem == "PyPI (Pip)": osv_ecosystem = "PyPI"

    all_queries = []
    all_pkg_names = []

    for name, ver in packages_dict.items():
        clean_ver = ver.lstrip("v")
        all_queries.append({
            "package": {"name": name, "ecosystem": osv_ecosystem},
            "version": clean_ver
        })
        all_pkg_names.append(name)

    total_pkgs = len(all_queries)
    if total_pkgs == 0: return {}

    vuln_map = {}
    num_batches = math.ceil(total_pkgs / BATCH_SIZE)

    batches_data = []
    for i in range(num_batches):
        start = i * BATCH_SIZE
        end = start + BATCH_SIZE
        batches_data.append((all_queries[start:end], all_pkg_names[start:end]))

    # ThreadPool Puro (Sem SQLite no meio para travar)
    # Podemos usar mais workers agora que não tem gargalo de arquivo
    with ThreadPoolExecutor(max_workers=10) as executor:
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
                logging.error(f"Batch thread error: {e}")

    return vuln_map


def process_batch(url, queries, names):
    local_map = {}
    # Sessão local por thread é mais segura e rápida
    session = requests.Session()

    try:
        response = session.post(url, json={"queries": queries}, timeout=45)

        if response.status_code == 200:
            results = response.json().get("results", [])

            for idx, res in enumerate(results):
                vulns = res.get("vulns", [])
                if vulns:
                    pkg_name = names[idx]

                    # Hydration Logic
                    full_vulns = []
                    for v in vulns:
                        # Se faltar dados, busca detalhe
                        if not v.get("summary") and not v.get("details"):
                            full_data = _hydrate_vulnerability(session, v.get("id"))
                            full_vulns.append(full_data if full_data else v)
                        else:
                            full_vulns.append(v)

                    local_map[pkg_name] = full_vulns
        else:
            logging.error(f"OSV API Error {response.status_code}: {response.text}")

    except Exception as e:
        logging.error(f"HTTP Request Error: {e}")
        raise e
    finally:
        session.close()

    return local_map


def _hydrate_vulnerability(session, vuln_id):
    if not vuln_id: return None
    try:
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        resp = session.get(url, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logging.warning(f"Failed to hydrate {vuln_id}: {e}")
    return None


def enrich_tree(node, vuln_map):
    if node.name in vuln_map:
        node.vulnerable = True
        node.vuln_details = vuln_map[node.name]

        count = len(node.vuln_details)
        if count > 0:
            first_id = node.vuln_details[0].get("id", "Unknown")
            node.vuln_summary = f"{count} vulns (e.g. {first_id})"
        else:
            node.vuln_summary = "Vulnerable"

    for child in node.children:
        enrich_tree(child, vuln_map)
