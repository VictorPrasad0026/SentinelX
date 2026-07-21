import dns.resolver
import dns.zone
import dns.query


def check_zone_transfer(domain):

    discovered = set()

    try:

        ns_records = dns.resolver.resolve(
            domain,
            "NS"
        )


        nameservers = [
            str(ns).rstrip(".")
            for ns in ns_records
        ]


        for ns in nameservers:

            try:

                zone = dns.zone.from_xfr(
                    dns.query.xfr(
                        ns,
                        domain,
                        timeout=5
                    )
                )


                for name in zone.nodes:

                    host = (
                        f"{name}.{domain}"
                    )

                    discovered.add(
                        host.lower()
                    )


            except Exception:

                continue


    except Exception:

        pass


    return discovered