# Zen 5 packed doubling leaf continuation — neutral result

Regime: cold strict n=1 verification on an AMD Ryzen 7 9700X, 1,232-byte
messages, pinned physical core 6, performance governor, `GOMAXPROCS=1`, and
Go 1.26.4. The baseline was feature-branch commit `e94e9be`.

The candidate shared the exact first-multiply assembly body between its
standalone leaf and a new continuation. After storing the same normalized
`[X^2,Y^2,Z^2,XY]` five-vector representation, the continuation tail-entered
the existing independently tested final-multiply leaf. It removed only one
return/call and the intervening `VZEROUPPER`; it did not change arithmetic,
range contracts, or the intermediate representation.

Focused native tests passed before measurement. Eight alternating two-second
public-API phases produced these microseconds/signature samples:

| path | samples | median |
|---|---|---:|
| baseline | 14.08, 14.15, 14.19, 14.30, 14.21, 14.08, 14.18, 14.17 | 14.175 |
| continuation | 14.00, 14.07, 14.21, 14.28, 14.15, 14.16, 14.28, 14.26 | 14.185 |

The distributions overlap completely and the candidate median is about 0.07%
slower. The candidate was removed. The result closes only the control-flow
continuation; a future fully fused leaf that also removes intermediate memory
transit would be a materially different experiment.

Command shape:

```sh
taskset -c 6 env GOMAXPROCS=1 ./PATH.test \
  -test.run='^$' \
  -test.bench='BenchmarkPublicR51VerifyBatchStrict/msg=1232/n=1$' \
  -test.benchmem -test.benchtime=2s -test.count=1
```
