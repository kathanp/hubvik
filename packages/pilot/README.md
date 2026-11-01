# @hubvik/pilot

UNVERIFIED. This package has not been run on a real device.

`hubvik-pilot` follows a conntrack log and a dnsmasq log on the box, writes checkpoints, takes labels from a local inbox, and writes a weekly report from those files. It does not open a network connection. The files stay on the device. Install `hubvik`, `@hubvik/adapter-conntrack`, and `@hubvik/adapter-dnsmasq` in the same project. This package does not declare them.

## Raspberry Pi OS

Install Node.js 22 or newer. Point `--conntrack` at a file that receives `conntrack -E -o timestamp`. Point `--dnsmasq` at the dnsmasq query log (`log-queries=extra`). Run `hubvik-pilot run --state /var/lib/hubvik --conntrack <file> --dnsmasq <file>` under systemd if you want it to restart.

## OpenWrt

The same command runs under procd on a router that has Node.js 22 or newer. Use the device's conntrack and dnsmasq log paths. Do not forward the state directory off the device.

## Privacy

State, events, and labels stay in `--state`. The package makes no network call. Redaction is not applied unless you wrap the logs before they reach this process.
