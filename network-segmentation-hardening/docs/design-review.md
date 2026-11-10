# Design review notes

## Assumptions

- A small office has separate user, server, management, and guest device groups.
- A firewall or Layer 3 gateway enforces inter-VLAN policy.
- Only management workstations should administer network devices.
- Business application ports must be confirmed with the service owner; this lab does not guess them.

## Security decisions

- Guest devices are isolated from internal VLANs and use firewall-controlled internet access.
- Management is a restricted administrative zone, not a general user network.
- Trunks explicitly allow the VLANs required by the design.
- Unused switch ports are disabled and placed in a reserved unused VLAN.
- PortFast and BPDU Guard are shown on endpoint access ports as a defensive baseline.

## Review before deployment

- Confirm switch and firewall syntax against actual platform documentation.
- Verify DHCP scopes, DNS, routing, and firewall rules for each VLAN.
- Confirm that trunk native VLAN handling matches both ends of the link.
- Ensure access points tag guest and corporate SSIDs as intended.
- Test both allowed and denied traffic paths, and record results.
- Provide an approved management access path and recovery procedure.

## Open questions for a real environment

- Which business applications and exact ports are required?
- Are voice, printers, IoT, or backup systems separate trust zones?
- How are administrator identities and MFA enforced?
- Which logging source records inter-VLAN denies and administrative changes?
- Who approves firewall exceptions and reviews them periodically?
