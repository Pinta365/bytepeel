---
max_turns: 20
timeout_seconds: 300
tags: [large, cbor, protobuf, nested]
---
A message envelope (CBOR, hex). Its `payload` is a protobuf order record whose field 3 is the shipping address (1 country, 2 city, 3 postal code).

```
a6617602636b6964696b6d732f65752f313763696174c11a6956dba0656e6f6e636550000102030405060708090a0b0c0d0e0f677061796c6f616458230a0a6f726465722d3766336b10041a130a025345120947c3b67465626f726718aac202646d657461a3677265747269657300666c61675f6d732b65726f75746583646564676564636f72656762696c6c696e67
```

What is the city and the postal code?

End your reply with one line in exactly this form:

ANSWER: <city> <postal code>
