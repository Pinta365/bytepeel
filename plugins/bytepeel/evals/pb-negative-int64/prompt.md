---
max_turns: 20
timeout_seconds: 300
tags: [protobuf, varint]
---
This is a protobuf message I pulled out of a gRPC log, as hex. We don't have the .proto, but field 1 is an `int64` account balance in cents.

```
08d4fdffffffffffffff011205616c6963651880e2cfaa06
```

What is the balance in field 1?

End your reply with one line in exactly this form:

ANSWER: <the integer value of field 1>
