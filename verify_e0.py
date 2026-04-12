from math import comb
from fractions import Fraction


def compute_E0(n, t, f):
    p = [Fraction(comb(n - f, t), comb(n - m, t)) for m in range(f + 1)]
    E = [Fraction(0)] * (f + 2)
    E[f] = Fraction(1)
    for m in range(f - 1, -1, -1):
        E[m] = 1 + (1 - p[m]) * E[m + 1]
    return p, E


def compute_E0_closed(n, t, f):
    p = [Fraction(comb(n - f, t), comb(n - m, t)) for m in range(f + 1)]
    result = Fraction(0)
    for m in range(f + 1):
        term = Fraction(1)
        for j in range(m):
            term *= (1 - p[j])
        result += term
    return result


def compute_E0_alpha(n, t, f, alpha):
    ps = []
    for m in range(f + 1):
        fm = f - m
        p_m = 1.0
        for k in range(t):
            h = (n - f) - k
            p_m *= h / (h + fm * alpha)
        ps.append(p_m)
    E = [0.0] * (f + 2)
    E[f] = 1.0
    for m in range(f - 1, -1, -1):
        E[m] = 1 + (1 - ps[m]) * E[m + 1]
    return ps, E


configs = [(5, 3, 2), (7, 4, 3), (10, 7, 3), (15, 10, 5)]
expected_p0 = [Fraction(1, 10), Fraction(1, 35), Fraction(1, 120), Fraction(1, 3003)]
expected_E0 = [Fraction(103, 40), Fraction(3153, 875), Fraction(43769, 11520), None]

for i, (n, t, f) in enumerate(configs):
    p, E = compute_E0(n, t, f)
    assert p[0] == expected_p0[i], f"p_0 mismatch for n={n}"
    if expected_E0[i] is not None:
        assert E[0] == expected_E0[i], f"E_0 mismatch for n={n}"
    assert compute_E0_closed(n, t, f) == E[0], f"Closed form mismatch for n={n}"

n, t, f = 5, 3, 2
p, E = compute_E0(n, t, f)
assert p == [Fraction(1, 10), Fraction(1, 4), Fraction(1, 1)]
assert E[2] == 1 and E[1] == Fraction(7, 4) and E[0] == Fraction(103, 40)

n, t, f = 7, 4, 3
p, E = compute_E0(n, t, f)
assert p == [Fraction(1, 35), Fraction(1, 15), Fraction(1, 5), Fraction(1, 1)]
assert E[2] == Fraction(9, 5) and E[1] == Fraction(67, 25)

n, t, f = 10, 7, 3
p, E = compute_E0(n, t, f)
assert p == [Fraction(1, 120), Fraction(1, 36), Fraction(1, 8), Fraction(1, 1)]

n, t, f = 5, 3, 2
ET = [sum(Fraction(1, n - m - k) for k in range(t)) for m in range(f + 1)]
assert ET == [Fraction(47, 60), Fraction(13, 12), Fraction(11, 6)]
p, _ = compute_E0(n, t, f)
reach = [Fraction(1)] * (f + 1)
for m in range(1, f + 1):
    reach[m] = reach[m - 1] * (1 - p[m - 1])
E_total = sum(reach[m] * ET[m] for m in range(f + 1))
assert E_total == Fraction(719, 240)

n, t, f = 7, 4, 3
expected_alpha = {0.5: 3.02, 1.0: 3.60, 2.0: 3.89, 5.0: 3.99}
for alpha, expected in expected_alpha.items():
    ps, E = compute_E0_alpha(n, t, f, alpha)
    assert abs(E[0] - expected) < 0.01, f"alpha={alpha}: E_0={E[0]:.2f} != {expected}"

