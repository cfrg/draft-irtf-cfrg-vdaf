One way of tightening the syntax in a way that fits both Prio and Heavy Hitters
is the following.

First, observe that validating the output requires a different number of rounds
for each protocol: Prio requires 1 and Heavy Hitters requires 2. What they both
have in common is that the computation of an aggregator's next message is a
function of the aggregator's (private) state and the *sum* of the (public)
messages from the previous round. Codifying this leads to a somewhat simpler
syntax.

As before, evaluation proceeds in rounds, where the messages output by each
aggregator in one round are used as input for the next round. What we do instead
is restrict the message space so that each aggregator outputs a vector of group
elements, and we say that the input for the next round is the *sum* of the
vectors.

In the new syntax, the VDAF now specifies an additive group `G` and a sequence
of "output lengths" `m` that determines the length of the output at each round.

 * `eval_setup() -> (pk, sk)`. Same as the old setup algorithm. Returns a
   public key used by the clients and the corresponding secret keys of the
   aggregators (`len(sk) == s`, where `s` is the number of aggregators).

 * `eval_input(pk, m) -> x`. Same as the old input-distribution algorithm. Takes
   in the input `m` and the public key and outputs a sequence of input shares
   (`len(x) == s`).

 * `eval_next(sk, n, p, x, y, i) -> y`. Subsumes the old verify-start,
   verify-next, and verify-finish algorithms of the current syntax. Inputs are:

      1. `k` The aggregator's secret key
      2. `n` The nonce
      3. `p` The aggregation parameter
      4. `x` The aggregator's input share
      5. `y` The *sum* of the previous round of messages, a vector of elements
         of G
      6. `i` The current round

    The output is a sequence of elements of `G` of length `m[i-1]`.

Evaluation of the VDAF on aggregation parameter `p`, nonces `nonces`, and inputs
`inputs` would look something like this (using Python as pseudocode):

```
def run(p, nonces, inputs):
  (pk, sk) = eval_setup()
  agg = [ 0 for j in range(s) ] # Aggregators' aggregate shares

  for (n, m) in zip(nonces, inputs):
    x = eval_input(pk, m)

    # Evaluate VDAF on input shares.
    y = 0
    out = [ 0 for j in range(s) ] # Aggregators' output shares
    for i in range(r+1):
      for j in range(s):
        out[j] = eval_next(sk[j], n, p, x[j], y)
      y = sum(out) # Input of next round is sum of this round.

    # Aggregate output shares.
    for j in range(s):
      agg[j] += out[j]

  # Recover aggregate.
  return sum(agg)
```

