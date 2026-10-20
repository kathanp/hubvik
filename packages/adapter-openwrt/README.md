# @iotwarden/adapter-openwrt

UNVERIFIED. Reads logread lines:

- `DHCPACK(br-lan) 192.0.2.10 aa:bb:cc:dd:ee:ff host` → dhcp
- `odhcpd: dhcpv6 reply aa:bb:cc:dd:ee:ff 00:03` → dhcp v6
- `odhcpd: ra from aa:bb:cc:dd:ee:ff fe80::1` → nd
- `hostapd: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated` → wifi

Never calls `feed`.
