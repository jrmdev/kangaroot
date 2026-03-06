import ipaddress
import logging
from typing import List, Optional, Iterator, Dict
import dns.resolver

# Using the logging module is generally better than print() for applications,
# as it allows for configurable levels (e.g., DEBUG, INFO, ERROR) and output destinations.
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ADUtils:
    """
    A utility class for performing common DNS lookups related to Active Directory.
    """

    @staticmethod
    def is_ip_address(address: str) -> bool:
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def _execute_dns_query(self, query_name: str, record_type: str) -> Iterator[str]:
        try:
            answers = dns.resolver.resolve(query_name, record_type)
            # SRV records have a 'target' attribute for the hostname.
            # Other records can be converted directly to a string.
            for rdata in answers:
                target = getattr(rdata, 'target', rdata)
                yield str(target).rstrip('.')
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            logging.warning(f"DNS query for '{query_name}' [{record_type}] failed: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during DNS query for '{query_name}': {e}")

    def try_resolve(self, name, domain, nameserver):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]

        def resolve_hostname(host):
            try:
                answers = resolver.resolve(host, 'A')
                return str(answers[0].to_text())
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.Timeout):
                return None

        # 1. Try the name directly
        result = resolve_hostname(name)
        if result:
            return result

        # 2. If it's a bare name (not FQDN), try appending the domain
        if "." not in name:
            fqdn = f"{name}.{domain}"
            result = resolve_hostname(fqdn)
            if result:
                return result

        # 3. Fallback to resolving the domain name
        return self.find_pdc(domain)
   

    def find_pdc(self, domain: str) -> Optional[str]:
        # We only expect one PDC, so we take the first result from the query generator.
        query_name = f"_ldap._tcp.pdc._msdcs.{domain}"
        return next(self._execute_dns_query(query_name, 'SRV'), None)

    def find_all_dcs(self, domain: str) -> List[str]:
        query_name = f"_ldap._tcp.dc._msdcs.{domain}"
        return list(self._execute_dns_query(query_name, 'SRV'))

    def find_all_dcs_with_ips(self, domain: str) -> Dict[str, str]:
        dcs_with_ips = {}
        dc_hostnames = self.find_all_dcs(domain)
        for hostname in dc_hostnames:
            ip = self.resolve_hostname(hostname)
            if ip:
                dcs_with_ips[hostname] = ip
            else:
                logging.warning(f"Could not resolve IP for DC: {hostname}")
        return dcs_with_ips

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        if self.is_ip_address(hostname):
            return hostname
        return next(self._execute_dns_query(hostname, 'A'), None)

    def get_dc_hostname(self, dc_identifier: str, domain: str) -> Optional[str]:
        if not dc_identifier:
            return self.find_pdc(domain)

        if self.is_ip_address(dc_identifier):
            all_dcs_with_ips = self.find_all_dcs_with_ips(domain)
            for dc in all_dcs_with_ips:
                if all_dcs_with_ips[dc] == dc_identifier:
                    return dc
            return self.find_pdc(domain)
        
        # Assume it's a hostname and ensure it's an FQDN.
        hostname = dc_identifier
        if not hostname.lower().endswith(domain.lower()):
            hostname = f"{hostname}.{domain}"
        
        # As a final check, confirm the hostname is resolvable before returning.
        if self.resolve_hostname(hostname):
            return hostname
        
        logging.warning(f"Could not validate or resolve the hostname '{hostname}'.")
        return None

    def get_dc_ip(self, dc_identifier: str, domain: str) -> Optional[str]:
        if dc_identifier == "":
            return next(self._execute_dns_query(self.find_pdc(domain), 'A'), None)


        if self.is_ip_address(dc_identifier):
            return dc_identifier

        if dc_identifier.count(".") == 0 and domain.count(".") > 0:
            dc_identifier += f".{domain}"

        hostname_to_resolve = dc_identifier
        if not hostname_to_resolve:
            logging.info(f"No DC identifier provided for {domain}, finding PDC to resolve.")
            hostname_to_resolve = self.find_pdc(domain)

        if hostname_to_resolve:
            return self.resolve_hostname(hostname_to_resolve)

        logging.error(f"Could not determine DC IP for '{dc_identifier}' in domain '{domain}'.")
        return None

    def get_dc_param(self, dc_identifier: str, domain: str) -> List[str]:
        target = dc_identifier if dc_identifier else self.find_pdc(domain)

        if not target:
            logging.error(f"Could not determine a DC target for domain '{domain}'.")
            return []

        if self.is_ip_address(target):
            return ['-dc-ip', target]
        else:
            return ['-dc-host', target]

    def ensure_ip_or_fqdn(self, host: str, domain: str) -> str:
        """
        Ensure host is either an IP address or FQDN.

        Args:
            host: Hostname, FQDN, or IP address
            domain: Domain name to append if needed

        Returns:
            IP address or FQDN
        """
        if self.is_ip_address(host):
            return host

        if host.count(".") > 0:
            return host

        # we must have a netbios name, try to resolve with the domain.
        ip = self.resolve_hostname(f"{host}.{domain}")
        return f"{host}.{domain}" if ip else host
