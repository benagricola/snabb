Usage:
  radish-profiler [OPTIONS]

  -h, --help                Print usage information
  -c, --config              Rule config file
  -i, --input               Interface for inbound (monitorable) traffic
  -o, --output              Interface for outboud traffic (send to another monitoring tool)
  -g, --group               Group identifier for aggregating traffic counters
  -n, --core                Core number to bind to (0-indexed)

Identify DDoS attacks - fast.

The interface(s) for clean and dirty traffic can be either Intel 10G cards
(based on 82599 chipset) or tap interfaces. If the specified interface is a PCI
ID to an existing 10G card the 10G driver will be used, otherwise tap
interfaces are assumed. If you wish to use tap interfaces, you need to create
the devices first:

    ip tuntap create dev dirty mode tap
    ip tuntap create dev clean mode tap
    ifconfig dirty up
    ifconfig clean up

The mitigation configuration file is in JSON format and lists the mitigations
that you want with rules for each mitigation. It is re-read every second and
when changes are detected the new config is loaded. Certain state loss is
associated with loading a new config which might lead to temporarily passing
packes that otherwise would have been blocked.

Example mitigations configuration file:

    {
        "rules": [
            {
                "name": "ntp",
                "filter": "udp and src port 123",
                "pps_rate": 10
            }
        ]
    }
