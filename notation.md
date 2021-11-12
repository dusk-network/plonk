# Notation (Prover)

## Common Preprocessed Input

## Public Input

## Prover Input

## Round 1

| Paper | Description | Implementation | Comment |
|-------|-------------|----------------|---------|
| Left wire polynomial | $a(X)$ | `w_l_poly` | We are not sure `w_l_poly` has the `(b_1*X+b_2)Z_H(X)` added (as it should)|
| Random blinding scalars | $b_1, b_2$ | ?? | We can not find them! |
| Commitment to left wire polynomial $a(x)$ | $[a(x)]_1$ | `w_l_poly_commit`  | |
|-------|-------------|----------------|---------|
| Right wire polynomial | $b(X)$ | `w_r_poly` | We are not sure `w_r_poly` has the `(b_3*X+b_4)Z_H(X)` added (as it should)|
| Random blinding scalars | $b_3, b_4$ | ?? | We can not find them! |
| Commitment to right wire polynomial $b(x)$ | $[b(x)]_1$             | `w_r_poly_commit`  | |
|-------|-------------|----------------|---------|
| Output wire polynomial | $c(X)$ | `w_o_poly` | We are not sure `w_o_poly` has the `(b_5*X+b_6)Z_H(X)` added (as it should)|
| Random blinding scalars | $b_5, b_6$ | ?? | We can not find them! |
| Commitment to output wire polynomial $c(x)$ | $[c(x)]_1$ | `w_o_poly_commit`  | |
|-------|-------------|----------------|---------|
| Fourth Wire polynomial | It is not in the paper | `w_4_poly` | We are not sure `w_4_poly` has the `(b_7*X+b_8)Z_H(X)` added (as it should)|
| Random blinding scalars | It is not in the paper $(b_7, b_8)$ | ?? | We can not find them! |
| Commitment to fourth wire polynomial | It is not in the paper | `w_4_poly_commit`  | |

## Round 2

| Paper | Description | Implementation | Comment |
|-------|-------------|----------------|---------|
| Compression factor | $\zeta$ | `zeta` | |
| Query vector | $\bf{f}$ | `compressed_f_multiset` | We should change it according to the new version of the protocol. |
| Table vector | $\bf{t}$ | `compressed_t_multiset` | |
| Sorted table vector | $\bf{t'}$ |  | |
| Vector $(f, t')$ sorted by $t'$ | $\bf{s}$ represented by   $\bf{h_1}$, $\bf{h_2}$|  | |
| Polynomial $h_1$ | $\bf{h_1}$, $\bf{h_2}$ |  | |
| Random blinding scalars | $b_9, b_{10}, b_{11}$ |  | |
| Polynomial $h_2$ | $\bf{h_1}$, $\bf{h_2}$ |  | |
| Random blinding scalars | $b_{12}, b_{13}$ |  | |


## Round 3

| Paper | Description | Implementation | Comment |
|-------|-------------|----------------|---------|
| Permutation challenge | $\beta$ | | |
| Permutation challenge | $\gamma$ | | |
| Permutation challenge | $\delta$ | | |
| Permutation challenge | $\epsilon$ | | |
| Permutation challenge | $\theta$ | | |
| Blinding scalars | $b_{14}\dots b_{19}$ | | |
| PlonK permutation polynomial | $z_1(X)$ | | |
| Commitment to PlonK permutation polynomial | $[z_1(x)]_1$ | | |
| PlonK mega permutation polynomial | $z_2(X)$ | | |
| Commitment to mega permutation polynomial | $[z_2(x)]_1$ | | |

## Round 4

| Paper | Description | Implementation | Comment |
|-------|-------------|----------------|---------|
| Quotient challenge | $\alpha$ | | |
| Quotient polynomial | $q(X)$ | | |
| Split of the quotient polynomial | $q_{\text{low}}(X), q_{\text{mid}}(X), q_{\text{high}}(X)$ | | |
| Commitments to the quotient polynomials | $[q_{\text{low}}(x)]_1, [q_{\text{mid}}(x)]_1, [q_{\text{high}}(x)]_1$ | | |

## Round 5

| Paper | Description | Implementation | Comment |
|-------|-------------|----------------|---------|
| Evaluation challenge | $\mathfrak{z}$ | | |
| Opening evaluation | $a(\mathfrak{z})$ | | |
| Opening evaluation | $b(\mathfrak{z})$ | | |
| Opening evaluation | $c(\mathfrak{z})$ | | |
| Opening evaluation | $S_{\sigma_1}(\mathfrak{z})$ | | |
| Opening evaluation | $S_{\sigma_2}(\mathfrak{z})$ | | |
| Opening evaluation | $q_K(\mathfrak{z})$ | | |
| Opening evaluation | $f(\mathfrak{z})$ | | |
| Opening evaluation | $t'(\mathfrak{z})$ | | |
| Opening evaluation | $h_2(\mathfrak{z})$ | | |
| Opening evaluation | $t(\mathfrak{z})$ | | |
| Opening evaluation | $z_1(w\mathfrak{z})$ | | |
| Opening evaluation | $t'(w\mathfrak{z})$ | | |
| Opening evaluation | $z_2(\mathfrak{z})$ | | |
| Opening evaluation | $h_1(\mathfrak{z})$ | | |

## Round 6

| Paper | Description | Implementation | Comment |
|-------|-------------|----------------|---------|
| Opening challenge | $v$ | | |
| Linearization polynomial | $r(X)$ | | |
| Opening proof polynomial 1 | $W_{\mathfrak{z}}(X)$ | | |
| Commitment to opening proof polynomial 1 | $[W_{\mathfrak{z}}(x)]_1$ | | |
| Opening proof polynomial 2 | $W_{\mathfrak{z}w}(X)$ | | |
| Commitment to opening proof polynomial 2 | $[W_{\mathfrak{z}w}(x)]_1$ | | |
| Multipoint evaluation challenge | $u$ | | |