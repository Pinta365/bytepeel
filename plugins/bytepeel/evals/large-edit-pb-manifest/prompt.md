---
max_turns: 20
timeout_seconds: 300
tags: [large, edit, protobuf, base64]
---
Deploy manifest, base64 protobuf:

```
CgxwYXltZW50cy1hcGkSBHByb2QakQEIAxJeCgNhcGkSK3JlZ2lzdHJ5LmV4YW1wbGUubmV0L3BheW1lbnRzL2FwaToyMDI2LjExLjIYkD8iEQoJTE9HX0xFVkVMEgRpbmZvIhQKBlJFR0lPThIKZXUtbm9ydGgtMRIkCgVlbnZveRIYZW52b3lwcm94eS9lbnZveTp2MS4zMi4xGK1NKgdyb2xsaW5neigAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYn
```

Field 3 is the spec: 3.1 is replicas, and each 3.2 is a container whose field 2 is its image. Set replicas to 300, and change the first container's image to `registry.example.net/payments/api:2026.11.14-hotfix.1`. Give me the new base64.

End your reply with one line in exactly this form:

ANSWER: <the base64>
