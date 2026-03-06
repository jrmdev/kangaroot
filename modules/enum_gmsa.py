import os
import shlex

from module import BaseModule
from tool import Tool


class GMSAEnum(BaseModule):
    path = "enum/gmsa"
    description = "Enumerate gMSA accounts and password retrieval exposure"
    options = {
        "dc_ip": {
            "default": "",
            "description": "DC IP or host address. If blank, the domain name will be used.",
            "required": False,
        },
        "domain": {
            "default": "",
            "description": "Auth: Domain name (FQDN)",
            "required": True,
        },
        "username": {"default": "", "description": "Auth: Username", "required": True},
        "password": {
            "default": "",
            "description": "Auth: Password or NT Hash (for NTLM auth only)",
            "required": False,
        },
        "auth": {
            "default": "ntlm",
            "description": "Auth: Type (ntlm, krb)",
            "required": True,
        },
        "resolve_sd": {
            "default": "Yes",
            "description": "Resolve security descriptors to principals where possible",
            "required": False,
            "boolean": True,
        },
        "include_consumers": {
            "default": "Yes",
            "description": "Enumerate objects referencing gMSA accounts via msDS-HostServiceAccount",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def _run_and_capture(self, command_parts: list[str]) -> list[str]:
        captured = []
        async for line in self.run_command(shlex.join(command_parts), self.pane_b):
            self.pane_b.write(line)
            captured.append(line)
        return captured

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)

        tool = Tool(self)
        tool.set_output_pane(self.pane_b)
        if not tool.set_auth(from_module=True):
            return

        auth_params = tool.get_auth_params("bloodyad")
        if not auth_params:
            return

        base = [
            "../tools/.bin/bloodyAD",
            "--host",
            self.opts.dc_hostname,
            "--dc-ip",
            self.opts.dc_ip,
        ] + auth_params

        outputs = []
        gmsa_count = 0
        consumer_count = 0
        broad_reader_hits = 0
        had_bloodyad_error = False
        no_result_filters = set()
        broad_reader_markers = (
            "authenticated users",
            "domain users",
            "everyone",
            "pre-windows 2000 compatible access",
        )

        self.pane_a.write("[cyan]Step 1:[/cyan] Enumerate gMSA account objects")
        command_parts = base + [
            "get",
            "search",
            "--base",
            "DOMAIN",
            "--filter",
            "(objectClass=msDS-GroupManagedServiceAccount)",
            "--attr",
            "sAMAccountName,dNSHostName,servicePrincipalName,memberOf,description,msDS-GroupMSAMembership",
        ]
        if self.opts.resolve_sd == "Yes":
            command_parts.append("--resolve-sd")

        gmsa_lines = await self._run_and_capture(command_parts)
        outputs.extend(gmsa_lines)
        query_error, query_no_results = self.inspect_bloodyad_output(gmsa_lines)
        if query_error:
            had_bloodyad_error = True
            self.pane_a.write(
                "[yellow][!] bloodyAD returned an error while querying gMSA objects; results may be incomplete.[/yellow]"
            )
        no_result_filters.update(query_no_results)

        for line in gmsa_lines:
            lower = line.lower().strip()
            if lower.startswith("samaccountname:") and "$" in line:
                gmsa_count += 1
            if any(marker in lower for marker in broad_reader_markers):
                broad_reader_hits += 1

        if self.opts.include_consumers == "Yes":
            self.pane_a.write("[cyan]Step 2:[/cyan] Enumerate gMSA consumer objects")
            command_parts = base + [
                "get",
                "search",
                "--base",
                "DOMAIN",
                "--filter",
                "(msDS-HostServiceAccount=*)",
                "--attr",
                "sAMAccountName,distinguishedName,msDS-HostServiceAccount",
            ]
            consumer_lines = await self._run_and_capture(command_parts)
            outputs.extend(consumer_lines)
            query_error, query_no_results = self.inspect_bloodyad_output(consumer_lines)
            if query_error:
                had_bloodyad_error = True
                self.pane_a.write(
                    "[yellow][!] bloodyAD returned an error while querying gMSA consumers; results may be incomplete.[/yellow]"
                )
            no_result_filters.update(query_no_results)

            for line in consumer_lines:
                if line.lower().strip().startswith("samaccountname:"):
                    consumer_count += 1

        output = "\n".join(outputs)
        log_path = self.write_unique_log(output, f"gmsa_enum_{self.opts.domain}")
        if log_path:
            self.pane_a.write(f"✓ Saved gMSA enumeration output to `{log_path.name}`")

        self.pane_a.write(f"✓ Matched {gmsa_count} gMSA account line(s).")
        if self.opts.include_consumers == "Yes":
            self.pane_a.write(
                f"✓ Matched {consumer_count} gMSA consumer object line(s)."
            )

        if broad_reader_hits:
            self.pane_a.write(
                f"[yellow][!] Matched {broad_reader_hits} potential broad gMSA password-reader indicator line(s).[/yellow]"
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, identify those reader principals and test gMSA secret retrieval paths with your current access."
            )
        if had_bloodyad_error:
            self.pane_a.write(
                "[yellow][!] Skipping clean gMSA risk conclusion because bloodyAD reported runtime errors. Review raw output/log.[/yellow]"
            )
        elif no_result_filters and gmsa_count == 0 and consumer_count == 0:
            self.pane_a.write(
                f"[cyan]Info:[/cyan] No matching gMSA objects were returned for {len(no_result_filters)} LDAP query filter(s)."
            )
            self.pane_a.write(
                "[cyan]Tip:[/cyan] Next, broaden identity coverage or retry with stronger privileges to resolve gMSA ACLs and memberships."
            )
        elif not broad_reader_hits:
            self.pane_a.write(
                "[green]✓ No broad gMSA password-reader indicators were matched in parsed output.[/green]"
            )
            if gmsa_count:
                self.pane_a.write(
                    "[cyan]Tip:[/cyan] gMSA accounts exist; next, inspect delegated rights with `enum/acl` and look for Kerberoastable SPNs via `kerberos/targets`."
                )
