---
max_turns: 20
timeout_seconds: 300
tags: [protobuf, xxd]
---
`xxd` output of a protobuf config file:

```
00000000: 0a10 6465 7669 6365 2d63 6f6e 6669 672f  ..device-config/
00000010: 7633 1001 3a0c 0a05 776c 616e 3010 dc0b  v3..:...wlan0...
00000020: 1800 3a0b 0a04 6574 6830 10a8 4618 01    ..:...eth0..F..
```

Field 7 is a repeated interface entry (field 1 name, field 2 MTU). What is the MTU of the second interface?

End your reply with one line in exactly this form:

ANSWER: <the integer>
