# @iotwarden/adapter-ipfix

UNVERIFIED. Parses NetFlow v9 and IPFIX template set 2 / v9 template set 0, then data sets, for IPv4 source and destination (field ids 8 and 12), ports 7 and 11, protocol 4, octets 1, and packets 2. The template cache holds 256 templates.

`createParser().write(buffer)` returns flow events. It never calls `feed`.
