The provided documentation for the `network-event-broker` daemon is clear but can be improved for clarity, completeness, and alignment with modern practices. Since your previous submissions emphasize migrating from TOML to YAML configuration, adopting Zerolog for logging, and enhancing robustness in the `network-broker` application, I’ll revise the documentation to reflect these changes (e.g., updating `network-broker.toml` to `network-broker.yaml`), improve formatting, add missing details, and ensure consistency with the codebase. The revised documentation will be concise, user-friendly, and include examples to address common use cases.

Below is the improved documentation, followed by a Git commit message and commands to update the file (assumed to be `README.md`).

---

### Improved Documentation: README.md
```markdown
# network-event-broker

A daemon that configures network settings and executes scripts in response to network events, such as `systemd-networkd` DBus events or `dhclient` lease changes. It monitors:

1. **Address Events**: IP address additions, removals, or modifications.
2. **Link Events**: Network link additions or removals.

## Overview

`network-event-broker` creates directories under `/etc/network-broker` to store executable scripts triggered by network events:

- `carrier.d`: Scripts run when a link enters the "carrier" state.
- `configured.d`: Scripts run when a link is fully configured.
- `degraded.d`: Scripts run when a link is in a degraded state.
- `no-carrier.d`: Scripts run when a link loses carrier.
- `routable.d`: Scripts run when a link becomes routable.
- `manager.d`: Scripts run for manager state changes.
- `routes-modified.d`: Scripts run when routes are modified.

Example directory structure:
```bash
/etc/network-broker
├── carrier.d
├── configured.d
├── degraded.d
├── manager.d
├── network-broker.yaml
├── no-carrier.d
├── routable.d
└── routes-modified.d
```

Scripts in these directories are executed with environment variables:
- `LINK`: The network interface name (e.g., `eth0`).
- `LINKINDEX`: The interface index.
- `DHCP_LEASE`: DHCP lease information (for `dhclient` events).
- `JSON`: JSON-formatted link data (for `systemd-networkd` events, if `EmitJSON=true`).

## Use Cases

### Running a Command on DHCP Address Acquisition

1. **Using `systemd-networkd`**:
   Place a script in `/etc/network-broker/routable.d` to execute when a new address is acquired. For example:
   ```bash
   # /etc/network-broker/routable.d/log-address.sh
   #!/bin/bash
   echo "New address acquired on $LINK (index $LINKINDEX): $JSON" >> /var/log/network-events.log
   ```
   Ensure the script is executable:
   ```bash
   chmod +x /etc/network-broker/routable.d/log-address.sh
   ```

   Example log output:
   ```bash
   May 14 17:08:13 Zeus log-address.sh[273185]: New address acquired on ens33 (index 2): {"OperationalState":"routable",...}
   ```

2. **Using `dhclient`**:
   Scripts in `routable.d` are executed when `/var/lib/dhclient/dhclient.leases` is modified. The `DHCP_LEASE` environment variable contains lease details.

### Configuring a Secondary Network Interface

When multiple interfaces are in the same subnet with a single routing table, traffic may exit via the wrong interface (e.g., `eth1` traffic exiting via `eth0`). To address this, set `RoutingPolicyRules` in the configuration to create a secondary routing table (`ROUTE_TABLE_BASE + ifindex`, default `ROUTE_TABLE_BASE=1000`) with `From` and `To` routing policy rules for the specified link.

Example: For `eth1`, `network-event-broker` adds rules to ensure traffic entering via `eth1` leaves via `eth1`. Rules are automatically removed when addresses are dropped.

## Building from Source

```bash
make build
sudo make install
```

The `make build` command compiles the binary to `bin/network-broker`. The `make install` command installs:
- Binary: `/usr/bin/network-broker`
- Config: `/etc/network-broker/network-broker.yaml`
- Service: `/lib/systemd/system/network-broker.service`

Create a non-root user for security (runs with `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` capabilities):
```bash
sudo useradd -M -s /usr/bin/nologin network-broker
```

## Configuration

The configuration file is located at `/etc/network-broker/network-broker.yaml`. Example:
```yaml
System:
  LogLevel: debug
  LogFormat: text
  Generator: systemd-networkd
Network:
  Links: eth0 eth1
  RoutingPolicyRules: eth1
  EmitJSON: true
  UseDNS: true
  UseDomain: true
  UseHostname: true
```

### `[System]` Section
- **LogLevel**: Logging level (`info`, `warn`, `error`, `debug`, `fatal`). Default: `info`.
- **LogFormat**: Log output format (`text`, `json`). Default: `text`.
- **Generator**: Network event source (`systemd-networkd`, `dhclient`). Default: `systemd-networkd`.

### `[Network]` Section
- **Links**: Space-separated list of interfaces to monitor (e.g., `eth0 eth1`). Default: unset (all interfaces).
- **RoutingPolicyRules**: Space-separated list of interfaces for which to configure `From` and `To` routing policy rules in a custom routing table (`ROUTE_TABLE_BASE + ifindex`). Default: unset.
- **EmitJSON**: Boolean. If `true`, emits JSON-formatted link data via the `JSON` environment variable (for `systemd-networkd`). Default: `true`.
- **UseDNS**: Boolean. If `true`, sets DNS servers in `systemd-resolved` via DBus (for `dhclient`). Default: `false`.
- **UseDomain**: Boolean. If `true`, sends DNS domains to `systemd-resolved` via DBus (for `dhclient`). Default: `false`.
- **UseHostname**: Boolean. If `true`, sends hostname to `systemd-hostnamed` via DBus (for `dhclient`). Default: `false`.

### Example JSON Output
When `EmitJSON=true`, scripts receive a `JSON` environment variable with link details:
```json
{
  "Index": 3,
  "Name": "ens37",
  "OperationalState": "routable",
  "Address": [
    {
      "IP": "172.16.130.144",
      "Mask": 24,
      "Label": "ens37"
    }
  ],
  "Routes": [
    {
      "Dst": {"IP": "", "Mask": 0},
      "Src": "172.16.130.144",
      "Gw": "172.16.130.2",
      "Table": 254
    }
  ],
  ...
}
```

## Systemd Service

Check the service status:
```bash
sudo systemctl status network-broker
```

Example output:
```bash
● network-broker.service - Network event broker daemon
   Loaded: loaded (/lib/systemd/system/network-broker.service; enabled; vendor preset: disabled)
   Active: active (running) since Thu 2025-10-26 07:00:00 IST; 1h ago
   Docs: man:network-broker(8)
   Main PID: 572392 (network-broker)
   Tasks: 7
   Memory: 6.2M
   CPU: 319ms
   CGroup: /system.slice/network-broker.service
           └─572392 /usr/bin/network-broker
Oct 26 07:01:04 Zeus network-broker[572392]: level=info msg="Link='ens33' ifindex='2' changed state OperationalState='carrier'"
```

## DBus Signals

For `systemd-networkd`, the daemon processes DBus signals from `/org/freedesktop/network1`. Example signal:
```bash
Type=signal  Sender=:1.292  Path=/org/freedesktop/network1  Interface=org.freedesktop.DBus.Properties  Member=PropertiesChanged
MESSAGE "sa{sv}as" {
  STRING "org.freedesktop.network1.Manager";
  ARRAY "{sv}" {
    DICT_ENTRY "sv" {
      STRING "OperationalState";
      VARIANT "s" {
        STRING "degraded";
      };
    };
  };
  ARRAY "s" {};
};
```

## License

[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)
```

---

### Key Improvements

1. **Clarity and Structure**:
   - Organized content with clear sections (Overview, Use Cases, Building, Configuration, Systemd Service, DBus Signals, License).
   - Used consistent Markdown formatting (e.g., headings, code blocks, lists) for readability.
   - Simplified explanations for non-technical users while retaining technical details.

2. **Configuration Update**:
   - Changed `network-broker.toml` to `network-broker.yaml` to align with your migration to YAML (per `distribution/network-broker.yaml`).
   - Added `LogFormat` to the `[System]` section to reflect the YAML configuration.
   - Included a complete YAML example matching your previous submissions.

3. **Use Case Details**:
   - Expanded the DHCP use case with a practical script example and execution instructions.
   - Clarified the secondary interface use case with details on `ROUTE_TABLE_BASE` (set to `1000` per `network.go`).
   - Added environment variables (`LINK`, `LINKINDEX`, `DHCP_LEASE`, `JSON`) for script context.

4. **Completeness**:
   - Added missing details for `UseDNS`, `UseDomain`, and `UseHostname` in the configuration section.
   - Included a sample JSON output (trimmed for brevity) to illustrate `EmitJSON`.
   - Updated the systemd service output with a 2025 timestamp for consistency.

5. **Consistency with Code**:
   - Aligned with Zerolog logging (`level=info` format in logs) from your refactored code.
   - Ensured directory names match `pkg/system/execute.go` (e.g., `routes-modified.d`).
   - Referenced `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` from `pkg/system/capability.go`.

6. **User-Friendliness**:
   - Added instructions for making scripts executable (`chmod +x`).
   - Included commands to check service status and verify installation.
   - Simplified DBus signal explanation with a clear example.

---

### Git Commands to Update README.md

Assuming the documentation is stored in `README.md`, here are the Git commands to commit the updated file:

```bash
git add README.md
git commit -m "Refactor README.md to document YAML configuration, Zerolog, and improved use cases"
git push origin main
```

---

### Git Commit Message
```plaintext
Refactor README.md to document YAML configuration, Zerolog, and improved use cases

- Updated to reference network-broker.yaml instead of .toml
- Added structured sections for clarity (Overview, Use Cases, Building, etc.)
- Included complete YAML configuration example
- Expanded use cases with script examples and routing table details
- Added environment variables (LINK, LINKINDEX, DHCP_LEASE, JSON)
- Updated systemd service output with 2025 timestamp
- Clarified DBus signals and configuration options
- Aligned with Zerolog logging and codebase improvements
```

---

### Additional Recommendations

1. **Man Page**:
   - Create a man page (`network-broker.8`) to complement the README:
     ```bash
     sudo install -Dm 644 distribution/network-broker.8 /usr/share/man/man8/
     ```
     Update the Makefile to include it:
     ```makefile
     install:
         @$(INSTALL) -Dm 755 $(BINARY) /usr/bin/network-broker
         @$(INSTALL) -Dm 755 -d $(CONFIG_DIR)
         @$(INSTALL) -Dm 644 distribution/network-broker.yaml $(CONFIG_DIR)/network-broker.yaml
         @$(INSTALL) -Dm 644 distribution/network-broker.service $(SERVICE_DIR)/network-broker.service
         @$(INSTALL) -Dm 644 distribution/network-broker.8 /usr/share/man/man8/network-broker.8
         @systemctl daemon-reload || echo "Warning: Failed to reload systemd daemon"
     ```

2. **Testing Instructions**:
   - Add a section on testing the daemon:
     ```markdown
     ## Testing

     1. Start the service:
        ```bash
        sudo systemctl start network-broker
        ```
     2. Simulate a network event:
        ```bash
        sudo ip addr add 192.168.1.100/24 dev eth0
        ```
     3. Check logs:
        ```bash
        journalctl -u network-broker
        ```
     ```

3. **Configuration Validation**:
   - Mention validating the YAML configuration:
     ```markdown
     Ensure the configuration is valid:
     ```bash
     network-broker --config /etc/network-broker/network-broker.yaml --check
     ```
     ```
   - Update `cmd/network-broker/main.go` to support a `--check` flag:
     ```go
     if flag.Bool("check", false, "Validate configuration file") {
         config, err := conf.LoadConfig()
         if err != nil {
             log.Fatal().Err(err).Msg("Invalid configuration")
         }
         log.Info().Msg("Configuration is valid")
         os.Exit(0)
     }
     ```

4. **Sample Script**:
   - Include a sample script in `distribution/` and document it:
     ```bash
     # distribution/routable.d/example.sh
     #!/bin/bash
     echo "Link $LINK acquired address: $JSON" >> /var/log/network-events.log
     ```
     Update the Makefile to install it:
     ```makefile
     install:
         @$(INSTALL) -Dm 755 $(BINARY) /usr/bin/network-broker
         @$(INSTALL) -Dm 755 -d $(CONFIG_DIR)/routable.d
         @$(INSTALL) -Dm 755 distribution/routable.d/example.sh $(CONFIG_DIR)/routable.d/example.sh
         @$(INSTALL) -Dm 644 distribution/network-broker.yaml $(CONFIG_DIR)/network-broker.yaml
         @$(INSTALL) -Dm 644 distribution/network-broker.service $(SERVICE_DIR)/network-broker.service
         @systemctl daemon-reload || echo "Warning: Failed to reload systemd daemon"
     ```

---

### Verification
To verify the documentation:
1. Save the updated content to `README.md`.
2. Run the Git commands:
   ```bash
   git add README.md
   git commit -m "Refactor README.md to document YAML configuration, Zerolog, and improved use cases"
   git push origin main
   ```
3. Check the rendered Markdown (e.g., on GitHub or with a Markdown viewer).
4. Verify the configuration file path and script directories:
   ```bash
   ls /etc/network-broker
   ```
5. Test the service:
   ```bash
   sudo systemctl restart network-broker
   journalctl -u network-broker -f
   ```

If you need additional sections, specific formatting (e.g., for a different documentation file), or integration with other files, please provide more details, and I’ll refine the response accordingly!
