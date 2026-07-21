PREFIXES=[
"dev",
"test",
"stage",
"staging",
"prod",
"api",
"admin"
]


SUFFIXES=[
"dev",
"test",
"01",
"02",
"prod"
]


def generate_permutations(subdomains,domain):

    generated=set()


    for sub in subdomains:

        name=sub.split(".")[0]


        for prefix in PREFIXES:

            generated.add(
                f"{prefix}-{name}.{domain}"
            )


        for suffix in SUFFIXES:

            generated.add(
                f"{name}-{suffix}.{domain}"
            )


    return generated