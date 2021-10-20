
# Distributed Aggregation Functions {#daf}

~~~~
client
  | input
  v
+-----------------------------------------------------------+
| daf_input()                                               |
+-----------------------------------------------------------+
  | input_shares[1]  | input_shares[2]   ...  | input_shares[SHARES]
  v                  v                        v
+---------------+  +---------------+        +---------------+
| daf_output()  |  | daf_output()  |        | daf_output()  |
+---------------+  +---------------+        +---------------+
  | output_shares[1] | output_shares[2]  ...  | output_shares[SHARES]
  v                  v                        v
aggregator 1       aggregator 2             aggregator SHARES
~~~~
{: #daf-flow title="Execution of a DAF."}

A DAF is a multi-party protocol for executing an aggregation function over a set
of user inputs. By distributing the input across multiple aggregators, the
protocol ensures that individual inputs are never seen in the clear.
Syntactically, a DAF is made up of two algorithms:

* `daf_input(input) -> input_shares: Vec[bytes]` is the randomized
  input-distribution algorithm. It is run by the client in order to split its
  input into `SHARES` input shares (i.e., `len(input_shares) == SHARES`). Each
  input share is sent to one of the aggregators.

* `daf_output(param, input_share) -> output_share` is the deterministic
  output-recovery algorithm. It is run be each aggregator in order to map an
  input share to an output share. This mapping has a parameter `param`, which
  can be used to "query" the input share multiple times with multiple
  parameters, getting a different output share each time. `param` is called the
  aggregation parameter.

Execution of a DAF is illustrated in {{daf-flow}}. The client runs the
input-distribution algorithm and sends an input share to each one of the
aggregators. Next, the aggregators select an aggregation parameter for querying
the input shares, and each runs the output-recover algorithm to obtain their
share of the output. DAF schemes are designed to ensure that no proper subset of
the aggregators can discern any information about the input or output given
their view of the protocol. (See {{security-considerations}}.)

Associated constants:

* `SHARES: Unsigned` is the number of aggregators for which the DAF is defined.

## Aggregability

<!--- An example of a DAF is a "Distributed Point Function" {{GI14}} protocol
for computing a "point function". A point function evaluates to zero on every
input except for one, called the "point". The input-distribution algorithm takes
in the point and the non-zero value and returns a set of input shares.
Aggregators can evaluate their shares at specific points and combine their
shares to get the results.

Another, slightly simpler example of a DAF is the combination of a linear secret
sharing scheme with an "AFfine-aggregatable Encoding (AFE)" described in the
original Prio paper [CGB17]. An AFE represents a measurement as a as a vector of
elements of a finite field such that (1) the measurement can be efficiently
secret shared and (2) the aggregate statistic can be computed by summing up the
vectors.  -->

Let `G(agg_param)` denote the support of the output-recovery algorithm for a
given aggregation parameter `agg_param`. That is, set `G(agg_param)` contains
the set of all possible outputs of the output-recovery algorithm when the first
input is `agg_param` and the second is any input share.

Correctness requires that, for every `agg_param`, the set `G(agg_param)` forms
an additive group. This allows the aggregation function to be computed by having
each aggregator sum up its output shares locally, then collectively computing
the output by summing up their aggregated output shares. In particular, the
aggregation function is computed by the following algorithm. (let
`Zero(agg_param)` denote the identity element of `G(agg_param)`):

~~~
def run_daf(agg_param, inputs: Set[bytes]):
  output_shares = [ Zero(agg_param) for _ in range(SHARES) ]

  for input in inputs:
    # Each client runs the input-distribution algorithm.
    input_shares = daf_input(input)

    # Each aggregator runs the output-recvoery algorithm.
    for j in range(SHARES):
      output_shares[j] += daf_output(agg_param, input_shares[j])

  # Aggregators compute the final output.
  return sum(output_shares)
~~~
{: #run-daf title="Definition of the aggregation function computed by a DAF."}
