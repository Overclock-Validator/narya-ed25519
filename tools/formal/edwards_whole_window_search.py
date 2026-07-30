#!/usr/bin/env python3
"""
Proof-oriented bounded search for a repeated Edwards25519 window.

Target window
-------------
    n chained doublings -> one affine/projective Niels addition -> ready P2/P3

The search models the Narya r51/u52 contract:
- IFMA multiplication and squaring inputs are carried u52 values.
- A raw folded field product is below the proved per-limb u61 bounds.
- One carry/fold normalizes one non-negative uint64 field value to u52.
- Point doubling returns a completed/P1P1 state E,F,G,H before conversion.

Formula choices
---------------
S: E = (X+Y)^2 - X^2 - Y^2
D: E = 2XY

Boundary choices
----------------
materialize:
    Convert the final completed point to ready X,Y,Z,T, then form Y-X/Y+X.
fuse_xy:
    Form raw X=EF and Y=GH, carry raw Y-X and Y+X directly. Carry Z and T.
fuse_xy_zraw:
    Affine-Niels only. As above, but feed raw Z=FG directly into the existing
    Niels Stage-2 contract, which already accepts D as an exact raw product.

This is an arithmetic-DAG and exact-range experiment, not a native benchmark.
Its optimality claims are only within the declared grammar.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from itertools import product
import argparse
import csv
import json
import math
import random
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Sequence, Tuple


# ---------------------------------------------------------------------------
# Dependency DAG
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Metrics:
    squarings: int
    multiplications: int
    carries: int
    carry_depth: int
    nonlinear_depth: int
    unit_arithmetic_depth: int


class DAG:
    def __init__(self) -> None:
        self.deps: Dict[str, Tuple[str, ...]] = {}
        self.kind: Dict[str, str] = {}
        self.users: Dict[str, List[str]] = defaultdict(list)

    def add(self, name: str, deps: Iterable[str] = (), kind: str = "L") -> str:
        if name in self.deps:
            raise ValueError(f"duplicate DAG node {name!r}")
        parents = tuple(deps)
        for parent in parents:
            if parent not in self.deps:
                raise ValueError(f"unknown dependency {parent!r} for {name!r}")
            self.users[parent].append(name)
        self.deps[name] = parents
        self.kind[name] = kind
        return name

    def terminals(self) -> List[str]:
        return [name for name in self.deps if not self.users.get(name)]

    def _longest_depth(self, sinks: Sequence[str], weights: Mapping[str, int]) -> int:
        memo: Dict[str, int] = {}

        def visit(node: str) -> int:
            if node in memo:
                return memo[node]
            parent = max((visit(p) for p in self.deps[node]), default=0)
            result = parent + weights.get(self.kind[node], 0)
            memo[node] = result
            return result

        return max((visit(sink) for sink in sinks), default=0)

    def metrics(self) -> Metrics:
        sinks = self.terminals()
        return Metrics(
            squarings=sum(kind == "S" for kind in self.kind.values()),
            multiplications=sum(kind == "M" for kind in self.kind.values()),
            carries=sum(kind == "C" for kind in self.kind.values()),
            carry_depth=self._longest_depth(sinks, {"C": 1}),
            nonlinear_depth=self._longest_depth(sinks, {"M": 1, "S": 1}),
            unit_arithmetic_depth=self._longest_depth(
                sinks, {"M": 1, "S": 1, "C": 1}
            ),
        )


@dataclass(frozen=True)
class SearchConfig:
    schedule: str
    ready_mask: int
    emit_intermediate_t: bool
    boundary: str
    table: str
    output: str


def _input(dag: DAG, name: str) -> str:
    return dag.add(name, kind="I")


def _carry(dag: DAG, name: str, value: str) -> str:
    return dag.add(name, [value], kind="C")


def _mul(dag: DAG, name: str, x: str, y: str) -> str:
    return dag.add(name, [x, y], kind="M")


def _square(dag: DAG, name: str, x: str) -> str:
    return dag.add(name, [x], kind="S")


def _linear(dag: DAG, name: str, *values: str) -> str:
    return dag.add(name, values, kind="L")


def build_window_dag(config: SearchConfig) -> DAG:
    schedule = config.schedule
    if not schedule or any(ch not in "SD" for ch in schedule):
        raise ValueError("schedule must be nonempty and use only S/D")
    if config.boundary not in {"materialize", "fuse_xy", "fuse_xy_zraw"}:
        raise ValueError("unknown boundary")
    if config.table not in {"affine", "projective"}:
        raise ValueError("unknown Niels table type")
    if config.output not in {"P2", "P3"}:
        raise ValueError("output must be P2 or P3")
    if config.boundary == "fuse_xy_zraw" and config.table != "affine":
        raise ValueError("raw-Z fusion requires an affine Niels table")
    if config.ready_mask >= (1 << max(0, len(schedule) - 1)):
        raise ValueError("ready_mask has bits outside the inter-doubling boundaries")

    dag = DAG()
    x, y, z = (_input(dag, name) for name in ("X0", "Y0", "Z0"))
    state_ready = True

    final_completed: Tuple[str, str, str, str] | None = None

    for index, formula in enumerate(schedule, start=1):
        raw_x, raw_y, raw_z = x, y, z
        if state_ready:
            cx, cy, cz = x, y, z
        else:
            cx = _carry(dag, f"d{index}_cX", raw_x)
            cy = _carry(dag, f"d{index}_cY", raw_y)
            cz = _carry(dag, f"d{index}_cZ", raw_z)

        a = _square(dag, f"d{index}_A", cx)
        b = _square(dag, f"d{index}_B", cy)
        c = _square(dag, f"d{index}_C", cz)

        if formula == "S":
            # When the incoming P2 is raw, carry(X+Y) can run in the same
            # dependency layer as carry(X), carry(Y), and carry(Z).
            u = _linear(dag, f"d{index}_XplusY", raw_x, raw_y)
            cu = _carry(dag, f"d{index}_cXplusY", u)
            s = _square(dag, f"d{index}_sum_square", cu)
            e = _linear(dag, f"d{index}_E", s, a, b)
        else:
            e = _mul(dag, f"d{index}_E", cx, cy)

        g = _linear(dag, f"d{index}_G", a, b)
        f = _linear(dag, f"d{index}_F", g, c)
        h = _linear(dag, f"d{index}_H", a, b)
        ce = _carry(dag, f"d{index}_cE", e)
        cf = _carry(dag, f"d{index}_cF", f)
        cg = _carry(dag, f"d{index}_cG", g)
        ch = _carry(dag, f"d{index}_cH", h)

        if index == len(schedule):
            final_completed = (ce, cf, cg, ch)
            break

        # P1P1/Completed -> P2. Leave the products raw unless this boundary
        # is deliberately materialized as a ready u52 P2.
        x = _mul(dag, f"d{index}_Xraw", ce, cf)
        y = _mul(dag, f"d{index}_Yraw", cg, ch)
        z = _mul(dag, f"d{index}_Zraw", cf, cg)

        if config.emit_intermediate_t:
            t_raw = _mul(dag, f"d{index}_dead_Traw", ce, ch)
            _carry(dag, f"d{index}_dead_cT", t_raw)

        boundary_bit = 1 << (index - 1)
        if config.ready_mask & boundary_bit:
            x = _carry(dag, f"d{index}_cXout", x)
            y = _carry(dag, f"d{index}_cYout", y)
            z = _carry(dag, f"d{index}_cZout", z)
            state_ready = True
        else:
            state_ready = False

    assert final_completed is not None
    ce, cf, cg, ch = final_completed

    q_plus = _input(dag, "Q_yplusx")
    q_minus = _input(dag, "Q_yminusx")
    q_t2d = _input(dag, "Q_t2d")
    q_z = _input(dag, "Q_z") if config.table == "projective" else None

    # Final doubling products. Production naming is:
    # X=E*F, Y=G*H, Z=F*G, T=E*H.
    p = _mul(dag, "boundary_Xraw_EF", ce, cf)
    q = _mul(dag, "boundary_Yraw_GH", cg, ch)
    r = _mul(dag, "boundary_Zraw_FG", cf, cg)
    u = _mul(dag, "boundary_Traw_EH", ce, ch)

    if config.boundary == "materialize":
        point_x = _carry(dag, "boundary_cX", p)
        point_y = _carry(dag, "boundary_cY", q)
        point_z = _carry(dag, "boundary_cZ", r)
        point_t = _carry(dag, "boundary_cT", u)
        y_minus_x_raw = _linear(dag, "add_YminusX_raw", point_y, point_x)
        y_plus_x_raw = _linear(dag, "add_YplusX_raw", point_y, point_x)
        y_minus_x = _carry(dag, "add_cYminusX", y_minus_x_raw)
        y_plus_x = _carry(dag, "add_cYplusX", y_plus_x_raw)
        d_input = point_z
    else:
        # Normalize the exact raw linear combinations, not X and Y separately.
        y_minus_x_raw = _linear(dag, "fused_YminusX_raw", q, p)
        y_plus_x_raw = _linear(dag, "fused_YplusX_raw", q, p)
        y_minus_x = _carry(dag, "fused_cYminusX", y_minus_x_raw)
        y_plus_x = _carry(dag, "fused_cYplusX", y_plus_x_raw)
        point_t = _carry(dag, "fused_cT", u)
        if config.boundary == "fuse_xy_zraw":
            d_input = r
        else:
            d_input = _carry(dag, "fused_cZ", r)

    add_a = _mul(dag, "add_A", y_minus_x, q_minus)
    add_b = _mul(dag, "add_B", y_plus_x, q_plus)
    add_c = _mul(dag, "add_C", point_t, q_t2d)
    if config.table == "projective":
        assert q_z is not None
        add_d = _mul(dag, "add_D", d_input, q_z)
    else:
        add_d = d_input

    add_e = _linear(dag, "add_E", add_b, add_a)
    add_f = _linear(dag, "add_F", add_d, add_c)
    add_g = _linear(dag, "add_G", add_d, add_c)
    add_h = _linear(dag, "add_H", add_b, add_a)
    cadd_e = _carry(dag, "add_cE", add_e)
    cadd_f = _carry(dag, "add_cF", add_f)
    cadd_g = _carry(dag, "add_cG", add_g)
    cadd_h = _carry(dag, "add_cH", add_h)

    out_x_raw = _mul(dag, "out_Xraw", cadd_e, cadd_f)
    out_y_raw = _mul(dag, "out_Yraw", cadd_g, cadd_h)
    out_z_raw = _mul(dag, "out_Zraw", cadd_f, cadd_g)
    _carry(dag, "out_X", out_x_raw)
    _carry(dag, "out_Y", out_y_raw)
    _carry(dag, "out_Z", out_z_raw)
    if config.output == "P3":
        out_t_raw = _mul(dag, "out_Traw", cadd_e, cadd_h)
        _carry(dag, "out_T", out_t_raw)

    return dag


# ---------------------------------------------------------------------------
# Exact interval/range proof for the fused affine boundary
# ---------------------------------------------------------------------------


RADIX = 1 << 51
IFMA_SPLIT = 1 << 52
WORD_LIMIT = 1 << 64
MODULUS_LIMBS = (RADIX - 19, RADIX - 1, RADIX - 1, RADIX - 1, RADIX - 1)
RAW_PRODUCT_UPPER = (
    267 * IFMA_SPLIT - 456,
    213 * IFMA_SPLIT - 366,
    159 * IFMA_SPLIT - 276,
    105 * IFMA_SPLIT - 186,
    51 * IFMA_SPLIT - 96,
)  # exclusive


def ceil_div(a: int, b: int) -> int:
    return -(-a // b)


def max_remainder(lower: int, upper: int, radix: int) -> int:
    if not (0 <= lower < upper):
        raise ValueError("invalid nonnegative interval")
    q_low = lower // radix
    q_high = (upper - 1) // radix
    if q_low != q_high:
        return radix - 1
    return (upper - 1) % radix


def carry_upper_exclusive(
    lowers: Sequence[int], uppers: Sequence[int]
) -> Tuple[int, ...]:
    if len(lowers) != 5 or len(uppers) != 5:
        raise ValueError("r51 requires five limbs")
    qmax = [(upper - 1) // RADIX for upper in uppers]
    rmax = [
        max_remainder(lower, upper, RADIX)
        for lower, upper in zip(lowers, uppers)
    ]
    maxima = [rmax[0] + 19 * qmax[4]]
    maxima.extend(rmax[i] + qmax[i - 1] for i in range(1, 5))
    return tuple(value + 1 for value in maxima)


def prove_fused_affine_ranges() -> dict:
    # Q - P with one positive and one negative exact raw product.
    bias = max(
        ceil_div(upper - 1, modulus_limb)
        for upper, modulus_limb in zip(RAW_PRODUCT_UPPER, MODULUS_LIMBS)
    )
    diff_lower = tuple(
        bias * modulus_limb - (upper - 1)
        for upper, modulus_limb in zip(RAW_PRODUCT_UPPER, MODULUS_LIMBS)
    )
    diff_upper = tuple(
        upper + bias * modulus_limb
        for upper, modulus_limb in zip(RAW_PRODUCT_UPPER, MODULUS_LIMBS)
    )
    sum_lower = (0, 0, 0, 0, 0)
    sum_upper = tuple(2 * upper - 1 for upper in RAW_PRODUCT_UPPER)
    raw_lower = (0, 0, 0, 0, 0)

    assert bias == 535
    assert min(diff_lower) >= 0
    assert max(diff_upper) < WORD_LIMIT
    assert max(sum_upper) < WORD_LIMIT
    assert max(RAW_PRODUCT_UPPER) < WORD_LIMIT

    carried_diff = carry_upper_exclusive(diff_lower, diff_upper)
    carried_sum = carry_upper_exclusive(sum_lower, sum_upper)
    carried_t = carry_upper_exclusive(raw_lower, RAW_PRODUCT_UPPER)
    assert max(carried_diff) <= IFMA_SPLIT
    assert max(carried_sum) <= IFMA_SPLIT
    assert max(carried_t) <= IFMA_SPLIT

    # Raw Z=F*G retains exact ifmaMulRaw provenance. The existing Niels Stage-2
    # contract accepts D as either that exact raw product or a u52 value.
    return {
        "radix": RADIX,
        "ifma_split": IFMA_SPLIT,
        "raw_product_upper_exclusive": list(RAW_PRODUCT_UPPER),
        "difference_bias_multiples_of_p": bias,
        "raw_y_minus_x_lower": list(diff_lower),
        "raw_y_minus_x_upper_exclusive": list(diff_upper),
        "raw_y_plus_x_upper_exclusive": list(sum_upper),
        "carried_y_minus_x_upper_exclusive": list(carried_diff),
        "carried_y_plus_x_upper_exclusive": list(carried_sum),
        "carried_t_upper_exclusive": list(carried_t),
        "all_uint64_safe": True,
        "all_carried_outputs_u52": True,
        "raw_z_preserves_exact_product_provenance": True,
    }


# ---------------------------------------------------------------------------
# Exact sparse-polynomial identities
# ---------------------------------------------------------------------------


Monomial = Tuple[int, ...]
Polynomial = Dict[Monomial, int]
POLY_VARS = ("e", "f", "g", "h", "qplus", "qminus", "qt2d")


def poly_const(value: int) -> Polynomial:
    return {tuple(0 for _ in POLY_VARS): value} if value else {}


def poly_var(index: int) -> Polynomial:
    exponent = [0] * len(POLY_VARS)
    exponent[index] = 1
    return {tuple(exponent): 1}


def poly_add(x: Polynomial, y: Polynomial) -> Polynomial:
    out = dict(x)
    for monomial, coefficient in y.items():
        out[monomial] = out.get(monomial, 0) + coefficient
        if out[monomial] == 0:
            del out[monomial]
    return out


def poly_neg(x: Polynomial) -> Polynomial:
    return {monomial: -coefficient for monomial, coefficient in x.items()}


def poly_sub(x: Polynomial, y: Polynomial) -> Polynomial:
    return poly_add(x, poly_neg(y))


def poly_mul(x: Polynomial, y: Polynomial) -> Polynomial:
    out: Polynomial = {}
    for mx, cx in x.items():
        for my, cy in y.items():
            monomial = tuple(a + b for a, b in zip(mx, my))
            out[monomial] = out.get(monomial, 0) + cx * cy
            if out[monomial] == 0:
                del out[monomial]
    return out


def poly_scale(x: Polynomial, scalar: int) -> Polynomial:
    return {m: scalar * c for m, c in x.items() if scalar * c}


def prove_symbolic_identities() -> dict:
    e, f, g, h, qplus, qminus, qt2d = [
        poly_var(index) for index in range(len(POLY_VARS))
    ]

    # Formula rewrite E=(X+Y)^2-X^2-Y^2 = 2XY.
    x = e
    y = f
    square_trick = poly_sub(
        poly_sub(poly_mul(poly_add(x, y), poly_add(x, y)), poly_mul(x, x)),
        poly_mul(y, y),
    )
    direct_xy = poly_scale(poly_mul(x, y), 2)
    assert square_trick == direct_xy

    point_x = poly_mul(e, f)
    point_y = poly_mul(g, h)
    point_z = poly_mul(f, g)
    point_t = poly_mul(e, h)

    # Materialized affine-Niels path.
    mat_a = poly_mul(poly_sub(point_y, point_x), qminus)
    mat_b = poly_mul(poly_add(point_y, point_x), qplus)
    mat_c = poly_mul(point_t, qt2d)
    mat_d = point_z
    mat_e = poly_sub(mat_b, mat_a)
    mat_f = poly_sub(poly_scale(mat_d, 2), mat_c)
    mat_g = poly_add(poly_scale(mat_d, 2), mat_c)
    mat_h = poly_add(mat_b, mat_a)
    mat_out = (
        poly_mul(mat_e, mat_f),
        poly_mul(mat_g, mat_h),
        poly_mul(mat_f, mat_g),
    )

    # Fused path substitutes the same completed-coordinate products directly.
    fused_a = poly_mul(poly_sub(poly_mul(g, h), poly_mul(e, f)), qminus)
    fused_b = poly_mul(poly_add(poly_mul(g, h), poly_mul(e, f)), qplus)
    fused_c = poly_mul(poly_mul(e, h), qt2d)
    fused_d = poly_mul(f, g)
    fused_e = poly_sub(fused_b, fused_a)
    fused_f = poly_sub(poly_scale(fused_d, 2), fused_c)
    fused_g = poly_add(poly_scale(fused_d, 2), fused_c)
    fused_h = poly_add(fused_b, fused_a)
    fused_out = (
        poly_mul(fused_e, fused_f),
        poly_mul(fused_g, fused_h),
        poly_mul(fused_f, fused_g),
    )

    assert (mat_a, mat_b, mat_c, mat_d) == (
        fused_a,
        fused_b,
        fused_c,
        fused_d,
    )
    assert mat_out == fused_out
    return {
        "direct_xy_identity": True,
        "fused_stage1_identity": True,
        "fused_ready_p2_output_identity": True,
        "output_polynomial_term_counts": [len(poly) for poly in fused_out],
        "maximum_output_total_degree": max(
            sum(monomial)
            for poly in fused_out
            for monomial in poly
        ),
    }


# ---------------------------------------------------------------------------
# Independent finite-field differential tests on Edwards25519
# ---------------------------------------------------------------------------


FIELD_P = 2**255 - 19
CURVE_D = (-121665 * pow(121666, FIELD_P - 2, FIELD_P)) % FIELD_P
BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BASE_Y = 46316835694926478169428394003475163141307993866256225615783033603165251855960
Affine = Tuple[int, int]
P2 = Tuple[int, int, int]
Completed = Tuple[int, int, int, int]


def inv(x: int) -> int:
    if x % FIELD_P == 0:
        raise ZeroDivisionError("field inversion of zero")
    return pow(x, FIELD_P - 2, FIELD_P)


def affine_add(p: Affine, q: Affine) -> Affine:
    x1, y1 = p
    x2, y2 = q
    cross = (CURVE_D * x1 * x2 * y1 * y2) % FIELD_P
    x3 = ((x1 * y2 + y1 * x2) * inv(1 + cross)) % FIELD_P
    y3 = ((y1 * y2 + x1 * x2) * inv(1 - cross)) % FIELD_P
    return x3, y3


def affine_scalar_mul(k: int, p: Affine) -> Affine:
    result = (0, 1)
    addend = p
    while k:
        if k & 1:
            result = affine_add(result, addend)
        addend = affine_add(addend, addend)
        k >>= 1
    return result


def affine_to_p2(point: Affine, scale: int) -> P2:
    x, y = point
    scale %= FIELD_P
    if scale == 0:
        raise ValueError("projective scale must be nonzero")
    return x * scale % FIELD_P, y * scale % FIELD_P, scale


def p2_to_affine(point: P2) -> Affine:
    x, y, z = point
    iz = inv(z)
    return x * iz % FIELD_P, y * iz % FIELD_P


def double_completed(point: P2, formula: str) -> Completed:
    x, y, z = point
    a = x * x % FIELD_P
    b = y * y % FIELD_P
    c = 2 * z * z % FIELD_P
    if formula == "S":
        e = ((x + y) * (x + y) - a - b) % FIELD_P
    elif formula == "D":
        e = 2 * x * y % FIELD_P
    else:
        raise ValueError("formula must be S or D")
    d = -a % FIELD_P
    g = (d + b) % FIELD_P
    f = (g - c) % FIELD_P
    h = (d - b) % FIELD_P
    return e, f, g, h


def completed_to_p2(completed: Completed) -> P2:
    e, f, g, h = completed
    return e * f % FIELD_P, g * h % FIELD_P, f * g % FIELD_P


def completed_to_p3(completed: Completed) -> Tuple[int, int, int, int]:
    e, f, g, h = completed
    return (
        e * f % FIELD_P,
        g * h % FIELD_P,
        f * g % FIELD_P,
        e * h % FIELD_P,
    )


def affine_niels(point: Affine) -> Tuple[int, int, int]:
    x, y = point
    return (y + x) % FIELD_P, (y - x) % FIELD_P, 2 * CURVE_D * x * y % FIELD_P


def materialized_final_add(completed: Completed, cached: Tuple[int, int, int]) -> P2:
    x, y, z, t = completed_to_p3(completed)
    qplus, qminus, qt2d = cached
    a = (y - x) * qminus % FIELD_P
    b = (y + x) * qplus % FIELD_P
    c = t * qt2d % FIELD_P
    d = z
    e = (b - a) % FIELD_P
    f = (2 * d - c) % FIELD_P
    g = (2 * d + c) % FIELD_P
    h = (b + a) % FIELD_P
    return e * f % FIELD_P, g * h % FIELD_P, f * g % FIELD_P


def fused_final_add(completed: Completed, cached: Tuple[int, int, int]) -> P2:
    e0, f0, g0, h0 = completed
    p = e0 * f0 % FIELD_P
    q = g0 * h0 % FIELD_P
    r = f0 * g0 % FIELD_P
    u = e0 * h0 % FIELD_P
    qplus, qminus, qt2d = cached
    a = (q - p) * qminus % FIELD_P
    b = (q + p) * qplus % FIELD_P
    c = u * qt2d % FIELD_P
    d = r
    e = (b - a) % FIELD_P
    f = (2 * d - c) % FIELD_P
    g = (2 * d + c) % FIELD_P
    h = (b + a) % FIELD_P
    return e * f % FIELD_P, g * h % FIELD_P, f * g % FIELD_P


def evaluate_window(point: P2, cached: Tuple[int, int, int], schedule: str) -> P2:
    current = point
    for formula in schedule[:-1]:
        current = completed_to_p2(double_completed(current, formula))
    final_completed = double_completed(current, schedule[-1])
    return fused_final_add(final_completed, cached)


def fused_add_to_completed(
    completed: Completed, cached: Tuple[int, int, int]
) -> Completed:
    """Fuse Completed -> affine-Niels Stage 2 and retain Completed output."""
    e0, f0, g0, h0 = completed
    p = e0 * f0 % FIELD_P
    q = g0 * h0 % FIELD_P
    r = f0 * g0 % FIELD_P
    u = e0 * h0 % FIELD_P
    qplus, qminus, qt2d = cached
    a = (q - p) * qminus % FIELD_P
    b = (q + p) * qplus % FIELD_P
    c = u * qt2d % FIELD_P
    return (
        (b - a) % FIELD_P,
        (2 * r - c) % FIELD_P,
        (2 * r + c) % FIELD_P,
        (b + a) % FIELD_P,
    )


def materialized_add_to_completed(
    completed: Completed, cached: Tuple[int, int, int]
) -> Completed:
    x, y, z, t = completed_to_p3(completed)
    qplus, qminus, qt2d = cached
    a = (y - x) * qminus % FIELD_P
    b = (y + x) * qplus % FIELD_P
    c = t * qt2d % FIELD_P
    return (
        (b - a) % FIELD_P,
        (2 * z - c) % FIELD_P,
        (2 * z + c) % FIELD_P,
        (b + a) % FIELD_P,
    )


def evaluate_multi_add_window(
    point: P2, cached_points: Sequence[Tuple[int, int, int]], schedule: str
) -> P2:
    current = point
    for formula in schedule[:-1]:
        current = completed_to_p2(double_completed(current, formula))
    completed = double_completed(current, schedule[-1])
    if not cached_points:
        return completed_to_p2(completed)
    for cached in cached_points[:-1]:
        completed = fused_add_to_completed(completed, cached)
    return fused_final_add(completed, cached_points[-1])


def differential_tests(seed: int = 0x51A6F00D, random_cases: int = 12) -> dict:
    rng = random.Random(seed)
    base = (BASE_X, BASE_Y)
    sqrt_minus_one = pow(2, (FIELD_P - 1) // 4, FIELD_P)
    torsion = ((0, 1), (0, FIELD_P - 1), (sqrt_minus_one, 0), ((-sqrt_minus_one) % FIELD_P, 0))

    cases: List[Tuple[Affine, Affine]] = []
    for index in range(random_cases):
        p = affine_scalar_mul(rng.randrange(1, 1 << 40), base)
        q = affine_scalar_mul(rng.randrange(1, 1 << 40), base)
        p = affine_add(p, torsion[index % len(torsion)])
        q = affine_add(q, torsion[(index * 3 + 1) % len(torsion)])
        cases.append((p, q))
    cases.extend(
        [
            ((0, 1), (0, 1)),
            ((0, FIELD_P - 1), base),
            ((sqrt_minus_one, 0), affine_add(base, (0, FIELD_P - 1))),
        ]
    )

    schedules = ["".join(chars) for chars in product("SD", repeat=6)]
    checked = 0
    exact_boundary_checks = 0
    for case_index, (p_affine, q_affine) in enumerate(cases):
        scale = rng.randrange(1, FIELD_P)
        p2 = affine_to_p2(p_affine, scale)
        cached = affine_niels(q_affine)
        expected = p_affine
        for _ in range(6):
            expected = affine_add(expected, expected)
        expected = affine_add(expected, q_affine)

        for schedule in schedules:
            current = p2
            for formula in schedule[:-1]:
                current = completed_to_p2(double_completed(current, formula))
            final_completed = double_completed(current, schedule[-1])
            materialized = materialized_final_add(final_completed, cached)
            fused = fused_final_add(final_completed, cached)
            if materialized != fused:
                raise AssertionError(
                    f"boundary mismatch case={case_index} schedule={schedule}"
                )
            exact_boundary_checks += 1
            got = p2_to_affine(fused)
            if got != expected:
                raise AssertionError(
                    f"group mismatch case={case_index} schedule={schedule}"
                )
            checked += 1

    # The fused/materialized identity is polynomial, so test arbitrary field
    # tuples too; no curve-validity assumption is needed for this equality.
    arbitrary_checks = 2_000
    two_add_arbitrary_checks = 0
    for _ in range(arbitrary_checks):
        completed = tuple(rng.randrange(FIELD_P) for _ in range(4))
        cached = tuple(rng.randrange(FIELD_P) for _ in range(3))
        if materialized_final_add(completed, cached) != fused_final_add(completed, cached):
            raise AssertionError("arbitrary-field fused identity failed")

        cached2 = tuple(rng.randrange(FIELD_P) for _ in range(3))
        materialized_mid = materialized_add_to_completed(completed, cached)
        fused_mid = fused_add_to_completed(completed, cached)
        if materialized_mid != fused_mid:
            raise AssertionError("arbitrary-field completed transition failed")
        if materialized_final_add(materialized_mid, cached2) != fused_final_add(
            fused_mid, cached2
        ):
            raise AssertionError("arbitrary-field two-add chain failed")
        two_add_arbitrary_checks += 1

    multi_add_checks = 0
    # Exercise zero, one, and two additions from the same six-double completed
    # boundary. This matches the two-term DSM control-flow envelope.
    for case_index, (p_affine, q_affine) in enumerate(cases):
        r_affine = affine_scalar_mul(17 + case_index, base)
        scale = rng.randrange(1, FIELD_P)
        p2 = affine_to_p2(p_affine, scale)
        cached_list = [affine_niels(q_affine), affine_niels(r_affine)]
        for schedule in schedules:
            doubled = p_affine
            for _ in range(6):
                doubled = affine_add(doubled, doubled)
            for additions in range(3):
                expected = doubled
                for addend in (q_affine, r_affine)[:additions]:
                    expected = affine_add(expected, addend)
                got = p2_to_affine(
                    evaluate_multi_add_window(p2, cached_list[:additions], schedule)
                )
                if got != expected:
                    raise AssertionError(
                        f"multi-add mismatch case={case_index} schedule={schedule} a={additions}"
                    )
                multi_add_checks += 1

    return {
        "valid_point_schedule_checks": checked,
        "exact_materialized_vs_fused_checks": exact_boundary_checks,
        "arbitrary_field_boundary_checks": arbitrary_checks,
        "arbitrary_field_two_add_chain_checks": two_add_arbitrary_checks,
        "zero_one_two_add_valid_point_checks": multi_add_checks,
        "schedules_per_case": len(schedules),
        "point_cases": len(cases),
        "included_identity_and_small_torsion": True,
    }


def mutation_tests(seed: int = 0xBAD51F00D) -> dict:
    """Ensure the proof gates reject several one-line defects."""
    rng = random.Random(seed)

    # Range mutation: 534*p is insufficient for one-negative-raw-product
    # subtraction under the proved exact-product interval.
    bad_bias = 534
    bad_lower = tuple(
        bad_bias * modulus_limb - (upper - 1)
        for upper, modulus_limb in zip(RAW_PRODUCT_UPPER, MODULUS_LIMBS)
    )
    bias_mutation_rejected = min(bad_lower) < 0
    if not bias_mutation_rejected:
        raise AssertionError("range checker failed to reject 534*p bias")

    # Algebra mutation: replace Y-X with Y+X in A.
    sign_mutation_rejected = False
    raw_z_mutation_rejected = False
    missing_t_mutation_rejected = False
    for _ in range(256):
        completed = tuple(rng.randrange(FIELD_P) for _ in range(4))
        cached = tuple(rng.randrange(FIELD_P) for _ in range(3))
        good = fused_final_add(completed, cached)
        e0, f0, g0, h0 = completed
        p0 = e0 * f0 % FIELD_P
        q0 = g0 * h0 % FIELD_P
        r0 = f0 * g0 % FIELD_P
        u0 = e0 * h0 % FIELD_P
        qplus, qminus, qt2d = cached

        def finish(a: int, b: int, c: int, d: int) -> P2:
            ee = (b - a) % FIELD_P
            ff = (2 * d - c) % FIELD_P
            gg = (2 * d + c) % FIELD_P
            hh = (b + a) % FIELD_P
            return ee * ff % FIELD_P, gg * hh % FIELD_P, ff * gg % FIELD_P

        bad_sign = finish(
            (q0 + p0) * qminus % FIELD_P,
            (q0 + p0) * qplus % FIELD_P,
            u0 * qt2d % FIELD_P,
            r0,
        )
        bad_z = finish(
            (q0 - p0) * qminus % FIELD_P,
            (q0 + p0) * qplus % FIELD_P,
            u0 * qt2d % FIELD_P,
            2 * r0 % FIELD_P,
        )
        bad_t = finish(
            (q0 - p0) * qminus % FIELD_P,
            (q0 + p0) * qplus % FIELD_P,
            0,
            r0,
        )
        sign_mutation_rejected |= bad_sign != good
        raw_z_mutation_rejected |= bad_z != good
        missing_t_mutation_rejected |= bad_t != good
        if sign_mutation_rejected and raw_z_mutation_rejected and missing_t_mutation_rejected:
            break

    results = {
        "bias_534_rejected": bias_mutation_rejected,
        "y_minus_x_sign_mutation_rejected": sign_mutation_rejected,
        "raw_z_extra_double_mutation_rejected": raw_z_mutation_rejected,
        "needed_t_omission_mutation_rejected": missing_t_mutation_rejected,
    }
    if not all(results.values()):
        raise AssertionError(f"mutation gate failed: {results}")
    return results


def build_all_direct_round_dag(
    n: int, additions: int, table: str = "affine"
) -> DAG:
    """Build the contextual-P2 fused DAG for n D doublings and a adds."""
    if n < 1 or additions < 0 or table not in {"affine", "projective"}:
        raise ValueError("invalid generalized round")
    dag = DAG()
    x, y, z = (_input(dag, name) for name in ("X0", "Y0", "Z0"))
    completed: Tuple[str, str, str, str] | None = None
    ready = True
    for index in range(1, n + 1):
        if ready:
            cx, cy, cz = x, y, z
        else:
            cx = _carry(dag, f"d{index}_cX", x)
            cy = _carry(dag, f"d{index}_cY", y)
            cz = _carry(dag, f"d{index}_cZ", z)
        aa = _square(dag, f"d{index}_A", cx)
        bb = _square(dag, f"d{index}_B", cy)
        cc = _square(dag, f"d{index}_C", cz)
        ee = _mul(dag, f"d{index}_E", cx, cy)
        gg = _linear(dag, f"d{index}_G", aa, bb)
        ff = _linear(dag, f"d{index}_F", gg, cc)
        hh = _linear(dag, f"d{index}_H", aa, bb)
        completed = (
            _carry(dag, f"d{index}_cE", ee),
            _carry(dag, f"d{index}_cF", ff),
            _carry(dag, f"d{index}_cG", gg),
            _carry(dag, f"d{index}_cH", hh),
        )
        if index != n:
            e0, f0, g0, h0 = completed
            x = _mul(dag, f"d{index}_Xraw", e0, f0)
            y = _mul(dag, f"d{index}_Yraw", g0, h0)
            z = _mul(dag, f"d{index}_Zraw", f0, g0)
            ready = False

    assert completed is not None
    if additions == 0:
        e0, f0, g0, h0 = completed
        ox = _mul(dag, "out_Xraw", e0, f0)
        oy = _mul(dag, "out_Yraw", g0, h0)
        oz = _mul(dag, "out_Zraw", f0, g0)
        _carry(dag, "out_X", ox)
        _carry(dag, "out_Y", oy)
        _carry(dag, "out_Z", oz)
        return dag

    for add_index in range(1, additions + 1):
        e0, f0, g0, h0 = completed
        p0 = _mul(dag, f"a{add_index}_Xraw", e0, f0)
        q0 = _mul(dag, f"a{add_index}_Yraw", g0, h0)
        r0 = _mul(dag, f"a{add_index}_Zraw", f0, g0)
        u0 = _mul(dag, f"a{add_index}_Traw", e0, h0)
        ymx = _carry(dag, f"a{add_index}_cYminusX", _linear(dag, f"a{add_index}_YminusX", q0, p0))
        ypx = _carry(dag, f"a{add_index}_cYplusX", _linear(dag, f"a{add_index}_YplusX", q0, p0))
        tt = _carry(dag, f"a{add_index}_cT", u0)
        qminus = _input(dag, f"a{add_index}_Qminus")
        qplus = _input(dag, f"a{add_index}_Qplus")
        qt2d = _input(dag, f"a{add_index}_Qt2d")
        av = _mul(dag, f"a{add_index}_A", ymx, qminus)
        bv = _mul(dag, f"a{add_index}_B", ypx, qplus)
        cv = _mul(dag, f"a{add_index}_C", tt, qt2d)
        if table == "projective":
            rz = _carry(dag, f"a{add_index}_cZ", r0)
            qz = _input(dag, f"a{add_index}_Qz")
            dv = _mul(dag, f"a{add_index}_D", rz, qz)
        else:
            dv = r0
        ev = _linear(dag, f"a{add_index}_E", bv, av)
        fv = _linear(dag, f"a{add_index}_F", dv, cv)
        gv = _linear(dag, f"a{add_index}_G", dv, cv)
        hv = _linear(dag, f"a{add_index}_H", bv, av)
        completed = (
            _carry(dag, f"a{add_index}_cE", ev),
            _carry(dag, f"a{add_index}_cF", fv),
            _carry(dag, f"a{add_index}_cG", gv),
            _carry(dag, f"a{add_index}_cH", hv),
        )

    e0, f0, g0, h0 = completed
    ox = _mul(dag, "out_Xraw", e0, f0)
    oy = _mul(dag, "out_Yraw", g0, h0)
    oz = _mul(dag, "out_Zraw", f0, g0)
    _carry(dag, "out_X", ox)
    _carry(dag, "out_Y", oy)
    _carry(dag, "out_Z", oz)
    return dag


def generalized_round_metrics(n: int = 6, max_additions: int = 2) -> List[dict]:
    """Closed-form all-direct round metrics for 0..max_additions adds.

    A fused affine transition maps Completed -> Completed in 7M and 7 carries.
    A fused projective transition costs 8M and 8 carries. The last transition
    emits ready P2; the final three products/carries are included in the closed
    forms below.
    """
    rows: List[dict] = []
    for additions in range(max_additions + 1):
        for table, per_add in (("affine", 7), ("projective", 8)):
            optimized = {
                "variant": "contextual-P2-fused",
                "table": table,
                "doublings": n,
                "additions": additions,
                "squarings": 3 * n,
                "multiplications": 4 * n + per_add * additions,
                "carries": 7 * n + per_add * additions,
                "carry_depth": 2 * n + 2 * additions,
                "t_products": additions,
            }
            rows.append(optimized)

            # A full-P3 baseline uses the existing direct-XY double and emits
            # P3 after every addition. Affine Niels is 7M/10 carries/3 layers;
            # projective Niels is 8M/10 carries/3 layers.
            baseline = {
                "variant": "full-P3-materialized",
                "table": table,
                "doublings": n,
                "additions": additions,
                "squarings": 3 * n,
                "multiplications": 5 * n + (7 if table == "affine" else 8) * additions,
                "carries": 8 * n + 10 * additions,
                "carry_depth": 2 * n + 3 * additions,
                "t_products": n + additions,
            }
            rows.append(baseline)
    return rows


# ---------------------------------------------------------------------------
# Search, Pareto filtering, and closed-form checks
# ---------------------------------------------------------------------------


def dominates(a: Mapping[str, int], b: Mapping[str, int], objectives: Sequence[str]) -> bool:
    no_worse = all(a[key] <= b[key] for key in objectives)
    strictly_better = any(a[key] < b[key] for key in objectives)
    return no_worse and strictly_better


def generate_rows(n: int = 6) -> List[dict]:
    rows: List[dict] = []
    boundaries = {
        "affine": ("materialize", "fuse_xy", "fuse_xy_zraw"),
        "projective": ("materialize", "fuse_xy"),
    }
    for chars in product("SD", repeat=n):
        schedule = "".join(chars)
        for ready_mask in range(1 << max(0, n - 1)):
            for emit_t in (False, True):
                for table, table_boundaries in boundaries.items():
                    for boundary in table_boundaries:
                        for output in ("P2", "P3"):
                            config = SearchConfig(
                                schedule=schedule,
                                ready_mask=ready_mask,
                                emit_intermediate_t=emit_t,
                                boundary=boundary,
                                table=table,
                                output=output,
                            )
                            metrics = build_window_dag(config).metrics()
                            row = {
                                **asdict(config),
                                **asdict(metrics),
                                "direct_count": schedule.count("D"),
                                "first_direct": schedule[0] == "D",
                                # Keep the certificate generator usable with the
                                # repository's Python 3.9 audit environment.
                                "ready_boundary_count": bin(ready_mask).count("1"),
                            }
                            rows.append(row)
    return rows


def closed_form_fused_affine_p2(schedule: str, ready_mask: int) -> Metrics:
    n = len(schedule)
    d = schedule.count("D")
    ready_before_standard = sum(
        bool(ready_mask & (1 << (index - 2))) and schedule[index - 1] == "S"
        for index in range(2, n + 1)
    )
    return Metrics(
        squarings=4 * n - d,
        multiplications=3 * n + d + 7,
        carries=8 * n + 7 - d,
        carry_depth=2 * n + 3 - int(schedule[0] == "D") + ready_before_standard,
        nonlinear_depth=2 * n + 2,
        # Unit arithmetic depth depends on whether the max path uses M or S,
        # but for this fixed node-weight model it is checked from the DAG below.
        unit_arithmetic_depth=-1,
    )


def verify_closed_forms(n: int = 6) -> dict:
    checked = 0
    for chars in product("SD", repeat=n):
        schedule = "".join(chars)
        for ready_mask in range(1 << max(0, n - 1)):
            config = SearchConfig(
                schedule=schedule,
                ready_mask=ready_mask,
                emit_intermediate_t=False,
                boundary="fuse_xy_zraw",
                table="affine",
                output="P2",
            )
            actual = build_window_dag(config).metrics()
            expected = closed_form_fused_affine_p2(schedule, ready_mask)
            for field in (
                "squarings",
                "multiplications",
                "carries",
                "carry_depth",
                "nonlinear_depth",
            ):
                if getattr(actual, field) != getattr(expected, field):
                    raise AssertionError(
                        f"closed form mismatch schedule={schedule} mask={ready_mask:0{n-1}b} "
                        f"field={field} actual={actual} expected={expected}"
                    )
            checked += 1

    # Contextual-coordinate theorem: n doublings followed by a additions save
    # exactly n T products relative to P3 after every point operation.
    t_checks = 0
    for doublings in range(1, 17):
        for additions in range(0, 5):
            full_p3_t_products = doublings + additions
            contextual_t_products = additions  # zero when a=0; otherwise final double + a-1 adds
            if full_p3_t_products - contextual_t_products != doublings:
                raise AssertionError("T-product saving theorem failed")
            t_checks += 1

    generalized_checks = 0
    for doublings in range(1, 9):
        for additions in range(0, 4):
            for table, per_add in (("affine", 7), ("projective", 8)):
                actual = build_all_direct_round_dag(doublings, additions, table).metrics()
                expected = {
                    "squarings": 3 * doublings,
                    "multiplications": 4 * doublings + per_add * additions,
                    "carries": 7 * doublings + per_add * additions,
                    "carry_depth": 2 * doublings + 2 * additions,
                }
                for field, want in expected.items():
                    if getattr(actual, field) != want:
                        raise AssertionError(
                            f"generalized DAG mismatch n={doublings} a={additions} "
                            f"table={table} field={field} actual={actual} want={want}"
                        )
                generalized_checks += 1

    return {
        "fused_closed_form_schedules_checked": checked,
        "contextual_t_theorem_cases_checked": t_checks,
        "generalized_zero_to_three_add_dags_checked": generalized_checks,
    }


def pareto_rows(rows: Sequence[dict], *, table: str, output: str) -> List[dict]:
    candidates = [
        row
        for row in rows
        if row["table"] == table
        and row["output"] == output
        and not row["emit_intermediate_t"]
    ]
    objectives = (
        "squarings",
        "multiplications",
        "carries",
        "carry_depth",
        "nonlinear_depth",
    )
    frontier: List[dict] = []
    # Collapse exact objective duplicates first and retain a representative with
    # the simplest representation policy.
    by_metrics: Dict[Tuple[int, ...], dict] = {}
    for row in candidates:
        key = tuple(row[obj] for obj in objectives)
        incumbent = by_metrics.get(key)
        if incumbent is None or (
            row["ready_boundary_count"], row["boundary"], row["schedule"]
        ) < (
            incumbent["ready_boundary_count"],
            incumbent["boundary"],
            incumbent["schedule"],
        ):
            by_metrics[key] = row
    unique = list(by_metrics.values())
    for row in unique:
        if not any(dominates(other, row, objectives) for other in unique if other is not row):
            frontier.append(row)
    frontier.sort(
        key=lambda row: tuple(row[obj] for obj in objectives)
        + (row["schedule"], row["boundary"])
    )
    return frontier


def summarize_key_rows(rows: Sequence[dict]) -> List[dict]:
    wanted = [
        # Production-shaped all-P3 baseline, affine Niels, ready boundaries.
        ("DDDDDD", (1 << 5) - 1, True, "materialize", "affine", "P3", "full-P3 baseline"),
        # Contextual coordinates but materialized final boundary.
        ("DDDDDD", 0, False, "materialize", "affine", "P2", "P2 chain, materialized boundary"),
        # Direct raw Y±X but normalized Z.
        ("DDDDDD", 0, False, "fuse_xy", "affine", "P2", "P2 chain, fused X/Y"),
        # Strongest affine candidate.
        ("DDDDDD", 0, False, "fuse_xy_zraw", "affine", "P2", "P2 chain, fused X/Y and raw Z"),
        # Multiplication-conservative depth-optimal mixed schedule.
        ("DSSSSS", 0, False, "fuse_xy_zraw", "affine", "P2", "mixed D+5S fused candidate"),
        # Projective-Niels analogue.
        ("DDDDDD", 0, False, "fuse_xy", "projective", "P2", "projective-Niels fused candidate"),
    ]
    index = {
        (
            row["schedule"],
            row["ready_mask"],
            row["emit_intermediate_t"],
            row["boundary"],
            row["table"],
            row["output"],
        ): row
        for row in rows
    }
    output_rows = []
    for schedule, mask, emit_t, boundary, table, output, label in wanted:
        row = dict(index[(schedule, mask, emit_t, boundary, table, output)])
        row["label"] = label
        output_rows.append(row)
    return output_rows


def write_csv(path: Path, rows: Sequence[dict]) -> None:
    fieldnames = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_report(
    path: Path,
    key_rows: Sequence[dict],
    range_proof: Mapping[str, object],
    symbolic: Mapping[str, object],
    differential: Mapping[str, object],
    checks: Mapping[str, object],
    mutations: Mapping[str, object],
    round_rows: Sequence[dict],
    row_count: int,
) -> None:
    table_header = (
        "| Candidate | S | M | carries | carry depth | nonlinear depth |\n"
        "|---|---:|---:|---:|---:|---:|"
    )
    table_lines = [table_header]
    for row in key_rows:
        table_lines.append(
            f"| {row['label']} | {row['squarings']} | {row['multiplications']} | "
            f"{row['carries']} | {row['carry_depth']} | {row['nonlinear_depth']} |"
        )

    round_table_header = (
        "| Table | additions | variant | S | M | carries | carry depth | T products |\n"
        "|---|---:|---|---:|---:|---:|---:|---:|"
    )
    round_table_lines = [round_table_header]
    for row in round_rows:
        round_table_lines.append(
            f"| {row['table']} | {row['additions']} | {row['variant']} | "
            f"{row['squarings']} | {row['multiplications']} | {row['carries']} | "
            f"{row['carry_depth']} | {row['t_products']} |"
        )

    baseline = key_rows[0]
    best = key_rows[3]
    md = f"""# Whole-window Edwards25519 synthesis: initial result

## Scope

This report studies a bounded arithmetic grammar for six Edwards25519
doublings followed by one Niels mixed addition in the r51/u52 IFMA model. It
is not a physical-CPU benchmark and does not establish literature novelty.

The grammar permits:

- conventional `S` and direct-XY `D` doubling formulas;
- raw or ready P2 boundaries between doublings;
- optional dead T reconstruction at intermediate boundaries;
- materialized or fused final-double-to-Niels transitions;
- affine or projective Niels tables;
- P2 or P3 output after the addition.

The search enumerated **{row_count:,}** concrete DAG configurations.

## Strongest candidate

Keep only `(X,Y,Z)` through the doubling chain. For the last doubling, retain
its carried completed coordinates `(E,F,G,H)` and form exact raw products:

```text
Xraw = E*F
Yraw = G*H
Zraw = F*G
Traw = E*H
```

Instead of carrying `Xraw` and `Yraw` separately and then carrying `Y-X` and
`Y+X`, form and carry the raw combinations directly:

```text
YmX = carry(Yraw + 535*p - Xraw)
YpX = carry(Yraw + Xraw)
T   = carry(Traw)
```

For an affine-Niels table, pass `Zraw` directly as Stage-2 `D`. The existing
Niels Stage-2 contract already accepts `D` as an exact raw product and computes
`2D±C` before its own carry pass.

The affine-Niels result is then emitted as ready P2, omitting the final `T`
because the next operation is another doubling.

## Metrics

{chr(10).join(table_lines)}

Relative to the full-P3 baseline in this model, the all-direct fused candidate
removes:

- **{baseline['multiplications'] - best['multiplications']} field multiplications**;
- **{baseline['carries'] - best['carries']} value-normalization carries**;
- **{baseline['carry_depth'] - best['carry_depth']} serial carry layer**.

Its multiplication count is lower because `T` is contextually dead after each
of the first five doublings and after the final addition. The boundary fusion
itself does not reduce multiplication count; it removes three carries without
adding a multiplication.

## Closed forms

For `n` doublings, `d` direct-XY choices, a raw P2 boundary before every later
standard doubling, the fused affine-Niels/P2 schedule has:

```text
squarings       = 4n - d
multiplications = 3n + d + 7
carries         = 8n + 7 - d
carry depth     = 2n + 3 - 1[first doubling is D]
nonlinear depth = 2n + 2
```

If a boundary immediately before a later `S` doubling is materialized as ready
P2, add one carry layer for each such boundary. Materializing before `D` moves
the required coordinate carries but does not change carry depth.

For six all-direct doublings, this gives:

```text
18S + 31M, 49 carries, carry depth 14.
```

The search independently rebuilt and checked every relevant DAG for all
schedules and all 32 inter-doubling ready/raw masks.

## Contextual-T theorem

For `n` doublings followed by `a` additions, where the next operation is a
doubling:

```text
full P3 after every point operation:  n + a T products
contextual P2/P3 schedule:            a T products
saving:                               n T products
```

If `a=0`, no T is needed. If `a>0`, the final doubling creates T for the first
addition and each non-final addition creates T for the next one; the final
addition emits P2. Therefore the saving is exactly the radix width, independent
of how many additions occur in the round.

For all-direct doublings, the resulting 0/1/2-addition round metrics are:

{chr(10).join(round_table_lines)}

The affine contextual/fused formulas are:

```text
squarings       = 3n
multiplications = 4n + 7a
carries         = 7n + 7a
carry depth     = 2n + 2a
T products      = a
```

For projective Niels, replace `7a` by `8a` in multiplications and carries.
The full-P3 materialized control uses `5n + 7a` affine multiplications,
`8n + 10a` carries, and carry depth `2n + 3a`.

## Range certificate for the fused boundary

The exact folded raw-product upper bounds are:

```text
{range_proof['raw_product_upper_exclusive']}
```

The minimum whole-modulus bias for `Yraw-Xraw` is exactly:

```text
{range_proof['difference_bias_multiples_of_p']} * p
```

Both `Yraw+Xraw` and the biased difference remain non-negative and below
`2^64`. One radix-51 carry/fold returns each to the u52 IFMA domain. `Traw`
likewise carries to u52. `Zraw` remains an exact raw-product value, satisfying
the provenance-sensitive input contract of Niels Stage 2.

Maximum carried exclusive bounds:

```text
Y-X: {range_proof['carried_y_minus_x_upper_exclusive']}
Y+X: {range_proof['carried_y_plus_x_upper_exclusive']}
T:   {range_proof['carried_t_upper_exclusive']}
```

## Verification performed

- Exact sparse-polynomial identity of the materialized and fused boundaries:
  `{symbolic['fused_ready_p2_output_identity']}`.
- Exact direct-XY rewrite identity: `{symbolic['direct_xy_identity']}`.
- Valid-point differential checks across all 64 S/D schedules:
  `{differential['valid_point_schedule_checks']}`.
- Arbitrary-field fused/materialized checks, requiring no curve assumption:
  `{differential['arbitrary_field_boundary_checks']}`.
- Closed-form DAG checks: `{checks['fused_closed_form_schedules_checked']}`.
- Contextual-T theorem checks: `{checks['contextual_t_theorem_cases_checked']}`.
- Explicit generalized 0-to-3-add DAG checks: `{checks['generalized_zero_to_three_add_dags_checked']}`.
- Valid-point 0/1/2-add checks across all S/D schedules: `{differential['zero_one_two_add_valid_point_checks']}`.
- Arbitrary-field two-add chain checks: `{differential['arbitrary_field_two_add_chain_checks']}`.
- Mutation gates:
  - 534p subtraction bias rejected: `{mutations['bias_534_rejected']}`;
  - `Y-X` sign mutation rejected: `{mutations['y_minus_x_sign_mutation_rejected']}`;
  - raw-Z extra-double mutation rejected: `{mutations['raw_z_extra_double_mutation_rejected']}`;
  - omission of a needed T rejected: `{mutations['needed_t_omission_mutation_rejected']}`.

The valid-point fixtures include the identity, order-2/order-4 torsion, and
mixed prime-order-plus-torsion points.

## Bounded lower bound

Within this grammar, carry depth 14 is optimal for six doublings plus an
affine-Niels add returning ready P2:

1. The first direct doubling needs one Stage-2 carry layer.
2. Each of the next five doublings needs one input-coordinate carry layer and
   one Stage-2 carry layer: ten more.
3. The final completed point needs one carry layer to create the u52
   `Y±X` and `T` multiplicands.
4. Niels Stage 2 needs one carry layer for its four outputs.
5. The ready P2 output needs one final carry layer.

Total: `1 + 10 + 1 + 1 + 1 = 14`.

The fused schedule attains every term of this lower bound. Beating it requires
leaving the current grammar, for example a multiply that legally consumes a
raw product, a different coordinate representation, or a wider multi-product
leaf with a separately proved range contract.

## Implementation shape

Use distinct types rather than an invalid/uninitialized `T` inside the current
extended point type:

```text
IFMAPointP2      = (X,Y,Z) u52
IFMACompleted    = (E,F,G,H) u52
IFMAPointP3      = (X,Y,Z,T) u52
```

Recommended leaves:

```text
doubleP2ToP2
lastDoubleP2ToCompleted
addCompletedAffineNielsToP2
addCompletedAffineNielsToP3   # only when another add follows
```

The four final-double products form a cycle over `E,F,G,H`. A destructive
schedule needs only one extra field-element slot, so the product phase has a
five-element storage lower bound/constructive schedule:

```text
P=E*F -> extra
R=F*G -> overwrite F
Q=G*H -> overwrite G
U=E*H -> overwrite E or H
```

The destructive product graph needs five field-element storage slots, but this
must not be confused with an all-register implementation. The current x8 raw
multiply schedule occupies Z0 through Z30, and the existing double and Niels
Stage-2 leaves occupy Z0 through Z26. Therefore a monolithic leaf cannot retain
all completed coordinates while reusing the present multiply body. The
apply-ready shape is workspace-resident and destructive: compute one raw
product at a time, overwrite dead completed slots, and use a small fused linear
and carry leaf at the boundary. An all-register version would require a new
streamed multiplication schedule and is a separate optimization problem.

## What is and is not new

Context-dependent P2/P3 conversion is established Edwards-scalar-multiplication
practice. The session-original bounded result is the exact r51/u52 accounting,
the raw `GH±EF` plus raw-Z fusion, and its carry-depth lower-bound match. A
literature search did not locate this exact fused IFMA boundary, but that is not
sufficient to claim global novelty.
"""
    path.write_text(md, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path("."))
    parser.add_argument("--random-cases", type=int, default=12)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    symbolic = prove_symbolic_identities()
    range_proof = prove_fused_affine_ranges()
    differential = differential_tests(random_cases=args.random_cases)
    checks = verify_closed_forms(6)
    mutations = mutation_tests()
    round_rows = generalized_round_metrics(6, 2)
    rows = generate_rows(6)
    key_rows = summarize_key_rows(rows)
    affine_frontier = pareto_rows(rows, table="affine", output="P2")
    projective_frontier = pareto_rows(rows, table="projective", output="P2")

    write_csv(args.out_dir / "edwards_whole_window_all_metrics.csv", rows)
    write_csv(args.out_dir / "edwards_whole_window_key_metrics.csv", key_rows)
    write_csv(args.out_dir / "edwards_whole_window_affine_pareto.csv", affine_frontier)
    write_csv(args.out_dir / "edwards_whole_window_projective_pareto.csv", projective_frontier)
    write_csv(args.out_dir / "edwards_round_addition_count_metrics.csv", round_rows)
    (args.out_dir / "edwards_whole_window_range_certificate.json").write_text(
        json.dumps(range_proof, indent=2) + "\n", encoding="utf-8"
    )
    verification = {
        "symbolic": symbolic,
        "range": range_proof,
        "differential": differential,
        "closed_form": checks,
        "mutations": mutations,
        "generalized_round_metrics": round_rows,
        "enumerated_dags": len(rows),
        "affine_p2_pareto_points": len(affine_frontier),
        "projective_p2_pareto_points": len(projective_frontier),
    }
    (args.out_dir / "edwards_whole_window_verification.json").write_text(
        json.dumps(verification, indent=2) + "\n", encoding="utf-8"
    )
    write_report(
        args.out_dir / "edwards_whole_window_initial_result.md",
        key_rows,
        range_proof,
        symbolic,
        differential,
        checks,
        mutations,
        round_rows,
        len(rows),
    )

    print(f"Enumerated {len(rows):,} DAG configurations.")
    print(f"Affine/P2 Pareto metric points: {len(affine_frontier)}")
    print(f"Projective/P2 Pareto metric points: {len(projective_frontier)}")
    print()
    print("Key configurations:")
    print("label                                      S   M   C  Cdepth  NLdepth")
    for row in key_rows:
        print(
            f"{row['label'][:42]:42s} {row['squarings']:2d}  {row['multiplications']:2d}  "
            f"{row['carries']:2d}    {row['carry_depth']:2d}       {row['nonlinear_depth']:2d}"
        )
    print()
    print(json.dumps({
        "symbolic": symbolic,
        "differential": differential,
        "checks": checks,
        "mutations": mutations,
        "generalized_round_metrics": round_rows,
    }, indent=2))


if __name__ == "__main__":
    main()
