---
max_turns: 20
timeout_seconds: 300
tags: [large, gzip, protobuf, varint]
---
Inventory snapshot from a cache, base64 of gzip of protobuf. Field 2 is a repeated item: 1 = sku (string), 2 = quantity (int32), 3 = price in cents (int64).

```
H4sIAAAAAAAC/zWRu2tUQRTGmbm7XFghOayFp/I/GJjnnZnCIq6b2Nrt3S5FIIWwYoh2QdwiiotB
LIIgaYQELFIIPtCsaKeNARUXUcRHIWIwCjFd1Jnx7i2H73yP323A+dmzc/O9xYU51ls43WOyCY38
eMm8FAJuEXywT5uTjXy6w4yTCg7h8FMWJe0uU0ZzWKG4t0yiZKpkzlgNs7j3hDYnGvlMyUzhLHTx
zWQUBNfCcgdH8fcqjR5TwdQrD48pjp6mlxBTcKHgJcHNlSwetUsmrfXwluD6YpScDEdccfhB8MuH
emrbZc6HnIcU3w9q1VHhpIUcv96tV0mauwJuh7b36lFyosuEVwqeE7yZp4Whvi4MnMKNX2lPWugF
CLx+OTFohSpcOjiC33/WKwbBQsIBwbVhkoRySmoBgwyvHI6SVoixRkOf4Ku1NDFQEZJruE9w+3VW
BWnhJCzh1UtZE/+31VbAwd/qI7izn0ekwc4IpaHEZ0tpeoAhuId+hv2LaVcrwrAW5nF1KxvnKWfg
EcFr27T6UYUwEs7h7kcyLmm8hV2C3/4kyUyHOWUEnMHBJq1wKRfoWByu18Z0pFYwCjOOJcRlQKw1
jCh+3km27Q4TutBwh+CL5Vp8CS7WWAnvKG7dqFXAnOcSJnBwgf4DL1JtNI0CAAA=
```

What is the quantity of sku AX-4471?

End your reply with one line in exactly this form:

ANSWER: <the integer>
