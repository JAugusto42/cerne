import httpx
import asyncio
import math
import logging

CONCURRENCY_LIMIT = asyncio.Semaphore(50)

async def check_vulnerabilities(packages_dict, ecosystem="Go", on_progress=None):
    """
    Async scanner utilizing HTTPX for high-performance network I/O.
    """
    logging.info(f"Scanning {len(packages_dict)} packages (Async Mode)...")

    url = "https://api.osv.dev/v1/querybatch"
    BATCH_SIZE = 250

    osv_ecosystem = ecosystem
    if ecosystem == "Go Modules": osv_ecosystem = "Go"
    if ecosystem == "RubyGems": osv_ecosystem = "RubyGems"
    if ecosystem in ["NPM", "NPM/Yarn"]: osv_ecosystem = "npm"
    if ecosystem == "PyPI (Pip)": osv_ecosystem = "PyPI"
    if ecosystem == "Cargo (Rust)": osv_ecosystem = "crates.io"

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

    limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
    
    async with httpx.AsyncClient(timeout=45.0, limits=limits) as client:
        tasks = []

        for i in range(num_batches):
            start = i * BATCH_SIZE
            end = start + BATCH_SIZE

            batch_queries = all_queries[start:end]
            batch_names = all_pkg_names[start:end]

            tasks.append(
                process_batch_safe(client, url, batch_queries, batch_names, on_progress, i + 1, num_batches)
            )

        results = await asyncio.gather(*tasks)

        for res in results:
            vuln_map.update(res)

    return vuln_map

async def process_batch_safe(client, url, queries, names, on_progress, current, total):
    async with CONCURRENCY_LIMIT:
        result = await process_batch(client, url, queries, names)
        if on_progress:
            on_progress(current, total)
        return result

async def process_batch(client, url, queries, names):
    local_map = {}
    try:
        response = await client.post(url, json={"queries": queries})

        if response.status_code == 200:
            results = response.json().get("results", [])
            hydration_tasks = []
            pending_hydrations = []

            for idx, res in enumerate(results):
                vulns = res.get("vulns", [])
                if vulns:
                    pkg_name = names[idx]

                    full_vulns = []
                    for v in vulns:
                        if not v.get("summary") and not v.get("details"):
                            task = _hydrate_vulnerability(client, v.get("id"))
                            hydration_tasks.append(task)
                            pending_hydrations.append((pkg_name, v, len(full_vulns)))
                            full_vulns.append(v)
                        else:
                            full_vulns.append(v)

                    if pkg_name not in local_map:
                        local_map[pkg_name] = []
                    local_map[pkg_name].extend(full_vulns)

            if hydration_tasks:
                hydrated_data = await asyncio.gather(*hydration_tasks)
                for i, data in enumerate(hydrated_data):
                    if data:
                        pkg_name, _, index = pending_hydrations[i]
                        local_map[pkg_name][index] = data

        else:
            logging.error(f"OSV API Error {response.status_code}: {response.text}")

    except Exception as e:
        logging.error(f"Async Request Error: {e}")

    return local_map

async def _hydrate_vulnerability(client, vuln_id):
    if not vuln_id: return None
    try:
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        resp = await client.get(url)
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
