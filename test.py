from collectors.subdomain_sources.recursive import (
    recursive_discovery
)


target = "github.com"


seed_hosts = {

    "api.github.com",

    "docs.github.com",

    "status.github.com",

    "gist.github.com"

}


results = recursive_discovery(

    domain=target,

    seed_hosts=seed_hosts,

    max_depth=1,

    max_queries=4

)


print(
    "\n========== RECURSIVE TEST ==========\n"
)


print(
    "Total discovered:",
    len(results)
)


print()


for host in sorted(results):

    print(
        host
    )