# Zen 4 direct strict singleton dispatch gate

This directory records the public `VerifyStrict` versus batch-of-one gate after
adding the private raw strict singleton backend seam.

Environment:

- AMD Ryzen 7 PRO 8700GE (Zen 4);
- Go 1.26.4, linux/amd64;
- one pinned core, `GOMAXPROCS=1`;
- six one-second samples per path and message size;
- zero allocations in every timed row.

The final direct path remains within 0.3-0.6% of batch-of-one for 200, 1232,
and 4096-byte messages. The immediately preceding 1232-byte gate measured the
old public path at about 19.60 µs and the direct path at about 17.46 µs, an
approximately 10.9% reduction.

`entrypoints.txt` SHA-256:

```text
4b54eaacc8c20702517dff4d432808e417302e41765a63674273088cecad83eb
```
