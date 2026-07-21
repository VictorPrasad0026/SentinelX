from collectors.subdomain_intelligence import get_subdomains

from collectors.subdomain_asset_enrichment import enrich_all_subdomains

import json



domain="github.com"



print("[+] Finding subdomains")


subs=get_subdomains(
    domain
)



print(
    "[+] Enriching assets"
)



assets=enrich_all_subdomains(
    subs
)



with open(
    "github_asset_inventory.json",
    "w"
) as f:


    json.dump(
        assets,
        f,
        indent=4
    )



print(
    "Completed"
)