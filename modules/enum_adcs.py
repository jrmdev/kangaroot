import shlex
import csv
import os
import re

from pathlib import Path
from rich.tree import Tree
from module import BaseModule
from tool import Tool


def display_csv_in_tree(csv_file, title, pane):
    with open(csv_file, "r") as f:
        reader = csv.reader(f, delimiter=";")
        headers = next(reader)
        rows = [row for row in reader]

    non_empty_columns = []
    header_map = {}
    for col_idx in range(len(headers)):
        header = headers[col_idx].strip()
        if header:
            non_empty_columns.append(col_idx)
            header_map[col_idx] = header

    tree = Tree(f"[bold cyan]{title}[/bold cyan]")
    for row_idx, row in enumerate(rows, 1):
        name_idx = headers.index("Name") if "Name" in headers else 0
        branch_label = row[name_idx].strip('"') if row[name_idx] else f"Row {row_idx}"
        branch = tree.add(f"[bold blue]{branch_label}[/bold blue]")
        for idx in non_empty_columns:
            if idx != name_idx:
                value = row[idx].strip('"').strip()
                if value:
                    if "\n" in value:
                        value = f"\n   " + "\n   ".join(value.splitlines())
                    branch.add(f"[bold]{header_map[idx]}:[/bold] {value}")
    pane.write(tree)
    pane.write("\n")


class ADCSEnum(BaseModule):
    path = "enum/adcs"
    description = "Enumerate ADCS CA to find vulnerable certificate templates"
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
        "register_globals": {
            "default": "No",
            "description": "Add global variables for CA Name and Host found (overwrite existing)",
            "required": False,
            "boolean": True,
        },
    }

    def __init__(self, registry, job_manager):
        super().__init__(registry, job_manager)

    async def run(self):
        if not self.validate_options():
            return

        os.chdir(self.logs_dir)
        tool = Tool(self)
        if not tool.set_auth(from_module=True):
            return

        fn1 = Path(f"{self.opts.domain}_CAs_Certipy.csv")
        fn2 = Path(f"{self.opts.domain}_Templates_Certipy.csv")

        if fn1.exists():
            fn1.unlink()
        if fn2.exists():
            fn2.unlink()

        if not await tool.certipy_find():
            return

        if fn1.exists():
            display_csv_in_tree(fn1, "Certificate Authorities", self.pane_c)

        if fn2.exists():
            display_csv_in_tree(fn2, "Certificate Templates", self.pane_c)

        if not fn1.exists():
            return

        cas = []
        vulns = set()
        esc_paths = set()

        with open(fn1, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=";")
            cas = list(reader)

        with open(fn2, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f, delimiter=";")
            templates = list(reader)

        for dct in cas:
            if "[!] Vulnerabilities" in dct:
                name = dct["CA Name"]
                vuln_list = dct["[!] Vulnerabilities"].splitlines()
                for v in vuln_list:
                    vulns.add(f"✓ CA '{name}' has {v}")
                    for esc in re.findall(r"ESC\d+", v.upper()):
                        esc_id = esc.lower()
                        if esc_id == "esc8":
                            esc_paths.update({"adcs/esc8_ntlm", "adcs/esc8_krb"})
                        else:
                            esc_paths.add(f"adcs/{esc_id}")

        for dct in templates:
            if "[!] Vulnerabilities" in dct:
                tpl = dct["Template Name"]
                vuln_list = dct["[!] Vulnerabilities"].split(", ")
                for v in vuln_list:
                    if len(v):
                        vulns.add(f"✓ Template '{tpl}' has {v}")
                        for esc in re.findall(r"ESC\d+", v.upper()):
                            esc_id = esc.lower()
                            if esc_id == "esc8":
                                esc_paths.update({"adcs/esc8_ntlm", "adcs/esc8_krb"})
                            else:
                                esc_paths.add(f"adcs/{esc_id}")

        if len(cas) and self.opts.register_globals == "Yes":
            self.registry.set_global_var("ca_name", cas[0]["CA Name"])
            self.pane_a.write(
                f"✓ Added global option `ca_name` => `{cas[0]['CA Name']}`"
            )

            self.registry.set_global_var("ca_host", cas[0]["DNS Name"])
            self.pane_a.write(
                f"✓ Added global option `ca_host` => `{cas[0]['DNS Name']}`"
            )

        if len(vulns):
            for v in sorted(list(vulns)):
                self.pane_a.write(v)
            if esc_paths:
                self.pane_a.write(
                    f"[cyan]Tip:[/cyan] Next, validate exploit paths with `{', '.join(sorted(esc_paths))}` based on the ESC findings above."
                )
            else:
                self.pane_a.write(
                    "[cyan]Tip:[/cyan] Next, review issued templates and test relevant ADCS abuse modules (`adcs/esc1` ... `adcs/esc16`)."
                )
        else:
            self.pane_a.write(
                "[cyan]Tip:[/cyan] No obvious ADCS vulns were parsed. Next, try `enum/acl` and `enum/delegation` for alternate privilege-escalation paths."
            )
