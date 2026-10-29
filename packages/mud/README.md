# @hubvik/mud

`parseMud(text)` and `loadMudFile(file)` turn a Manufacturer Usage Description file (RFC 8520 JSON) into `{ allows }`. Pass that object to `engine.loadMud(device, acl)`.

Accept rules become `dstPort`, `proto`, `domain`, and `direction` (`out` for from-device, `in` for to-device). Drop rules are skipped. More than 64 allows is rejected. The package does not fetch the MUD file and does not write firewall rules.
