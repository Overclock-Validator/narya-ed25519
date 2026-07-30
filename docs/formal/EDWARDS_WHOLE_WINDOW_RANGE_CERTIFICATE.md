# Edwards whole-window range certificate

## Status and scope

This is a bounded executable certificate for the r51/u52 arithmetic grammar,
not a general optimality theorem and not a proof of the emitted x86-64 binary.
It covers a chain of Edwards doublings followed by affine or projective Niels
additions, where IFMA operands are carried u52 values and raw products obey the
repository's five-limb folded-product bounds.

The supplied search enumerated **40,960** concrete DAG configurations. Narya
reproduced the search and all three generated artifacts byte for byte before
implementing the candidate. The original source artifact hashes were:

The bounded search and draft certificate were produced with OpenAI ChatGPT Pro
research assistance. OpenAI Codex independently reproduced the outputs, mapped
the stale six-doubling model onto the live five-doubling schedule, implemented
the native candidate and its separate oracle, and ran the native correctness
and performance gates. These AI systems are not cryptographic auditors; the
artifact remains subject to the proof boundary stated here.

| artifact | SHA-256 |
| --- | --- |
| search program | `3e2e0759e14e0dfd921f628a3c802d9c614238995dbcc668442fc1ac32e8b6f3` |
| range certificate | `26d5f75425c9c80720a91c8276902464b62f49d9632faf5e460b81cc5017ded8` |
| verification record | `67c82c7c5455ff52bbe2c47c487dc70e9e590ec099988085888b46679c03979a` |
| initial report | `874e72a3c81bbe9c34d3fdc0c641114a975e0cfa1dc6eeeec65168c15c0f7d47` |
| implementation plan | `cb1cf5429acfddbaba91437c22f197b23ea564e467036c36cbcc70603c5935d9` |

The checked-in source and JSON outputs are linked from
[`README.md`](README.md). The checked-in source contains one semantics-neutral
compatibility edit (`int.bit_count()` to `bin(x).count("1")`) so it also runs
under Python 3.9; the hash above identifies the original supplied source.
Regenerate with:

```sh
python3 tools/formal/edwards_whole_window_search.py \
  --out-dir /tmp/edwards-whole-window
```

## Certified boundary

The last doubling retains carried completed coordinates `(E,F,G,H)` and forms
the exact folded raw products:

```text
Xraw = E*F
Yraw = G*H
Zraw = F*G
Traw = E*H
```

Instead of carrying `Xraw` and `Yraw` separately and then carrying `Y-X` and
`Y+X`, the boundary forms:

```text
YMinusX = carry(Yraw + 535*p - Xraw)
YPlusX  = carry(Yraw + Xraw)
Z       = carry(Zraw)
T       = carry(Traw)
```

The independently derived exact folded-product upper bounds are:

```text
[1202461100507921976,
  959266720629915282,
  716072340751908588,
  472877960873901894,
  229683580995895200]
```

The certificate establishes, under its stated unsigned input bounds:

- `535*p` is the minimum whole-modulus bias that prevents underflow in
  `Yraw-Xraw`; the mutation to `534*p` is rejected;
- the biased difference and sum are non-negative and below `2^64`;
- one radix-51 carry/fold returns each output to the u52 IFMA domain;
- raw `Zraw` retains exact-product provenance when passed to the affine Niels
  Stage-2 contract.

The JSON certificate contains the exact lower and upper bound vector for every
one of those claims.

## Implementation mapping

Commit `5d8a3e4049f565e807e4b8e130de1ae55c3c429b` implements the boundary as an
unwired experiment:

- `ifmaCompletedPointX8` is a distinct completed-coordinate state, so code
  cannot accidentally read a missing `T` from a P2 point;
- `ifmaCompletedProductsToLinearUncheckedX8` is the native leaf covered by the
  range bounds above;
- `ifmaCompletedProductsToLinearModelX8` is the independently scheduled
  portable oracle;
- `IFMAAsymmetricFixedB10EvaluateWholeWindowExperimentX8` preserves the live
  radix-32/B10 scalar schedule and changes only the five-doubling boundary.

The implementation adapts the six-doubling research grammar to Narya's live
five-doubling radix-32 windows. It does not assume that an operation count from
the six-doubling model is a cycle prediction.

Native gates cover the maximum certificate vector, 10,000 raw differentials,
exact five-doubling representation equality, all 256 active masks, 512
randomized complete evaluator groups, alias-safe leaves, and zero allocations.
The search additionally records exact polynomial identities, 7,920 generated
differential checks across valid and arbitrary field inputs, contextual-T
closed forms, and four deliberate mutation rejections.

## Performance verdict

On the pinned Ryzen 7 9700X (Zen 5), nine two-second complete prepared-loop
samples measured:

| evaluator | median µs/x8 group | median µs/signature |
| --- | ---: | ---: |
| materialized live boundary | 19.324 | 2.416 |
| certified whole-window candidate | 19.221 | 2.403 |

The candidate improved the isolated prepared evaluator by approximately
**0.53%**. That is a valid small gain, but it does not justify replacing the
smaller, already-reviewed production boundary immediately before the safety
freeze. The experiment and its certificate remain in-tree with a regime tag;
the registered backend does not call it.

## Remaining proof gap

This evidence does not establish that the assembly bytes implement the oracle
for every machine state. Closing that gap would require a restricted x86-64
semantics and a refinement proof covering register mapping, memory addressing,
aliasing, unsigned arithmetic, `VPMADD52*` truncation, and the exact
`NORMALIZE_5` expansion. Until then, the native differentials and mutation
gates are strong testing evidence, not a substitute for independent assembly
review.
