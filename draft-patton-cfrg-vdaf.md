---
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is draft-<yourname>-<workgroup>-<name>.md
#
# Set the "title" field below at the same time.  The "abbrev" field should be
# updated too.  "abbrev" can be deleted if your title is short.
#
# You can edit the contents of the document as the same time.
# Initial setup only needs the filename and title.
# If you change title or name later, you can run the "Rewrite README" action.
#
# Do not include "-latest" in the file name.
# The tools use "draft-<name>-latest" to find the draft name *inside* the draft,
# such as the "docname" field below, and replace it with a draft number.
# The "docname" field below can be left alone: it will be updated for you.
#
# This template uses kramdown-rfc2629: https://github.com/cabo/kramdown-rfc2629
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
# Delete this comment when you are done.
#
title: "Verifiable Distributed Aggregation Functions"
abbrev: "VDAF"
docname: draft-patton-cfrg-vdaf-latest
category: info

ipr: trust200902
area: TODO
workgroup: TODO Working Group
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com

normative:

informative:

  AGJOP21:
    title: "Prio+: Privacy Preserving Aggregate Statistics via Boolean Shares"
    author:
      - ins: S. Addanki
      - ins: K. Garbe
      - ins: E. Jaffe
      - ins: R. Ostrovsky
      - ins: A. Polychroniadou
    target: https://ia.cr/2021/576
    date: 2021

  BBDGGI19:
    title: "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: CRYPTO 2019
    date: 2019

  BBDGGI21:
    title: "Lightweight Techniques for Private Heavy Hitters"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: IEEE S&P 2021
    date: 2021

  CGB17:
    title: "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"
    author:
      - ins: H. Corrigan-Gibbs
      - ins: D. Boneh
    seriesinfo: NSDI 2017
    date: 2017

  GI14:
    title: "Distributed Point Functions and Their Applications"
    author:
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: EUROCRYPT 2014
    date: 2014

  Dou02:
    title: "The Sybil Attack"
    date: 2002
    target: "https://link.springer.com/chapter/10.1007/3-540-45748-8_24"
    author:
      - ins: J. Douceur

  PAPER:
    title: "TODO"

  Vad16:
    title: "The Complexity of Differential Privacy"
    date: 2016
    target: "https://privacytools.seas.harvard.edu/files/privacytools/files/complexityprivacy_1.pdf"
    author:
      - ins: S. Vadhan

--- abstract

This document describes Verifiable Distributed Aggregation Functions (VDAFs), a
family of multi-party protocols for computing aggregate statistics over user
measurements. These protocols are designed to ensure that, as long as at least
one aggregation server executes the protocol honestly, individual measurements
are never seen by any server in the clear. At the same time, VDAFs allow the
servers to detect if a misconfigured or malicious client submitted a malformed
input.


--- middle

# Introduction

TODO Introduction

VDAFs from the literature:

* Prio [CGB17] defines the composition of a linear secret sharing scheme and an
  affine-aggregatable encoding of a statistic.

* A special case of zero-knowledge proofs over distributed data [BBDGGI19] in
  which the client speaks once.

* The composition of an incremental distributed point function and the
  secure-sketching protocol for subset histograms defined in [BBDGGI21].

* Prio+ [AGJOP21] has the client upload XOR shares and then has the servers
  convert them to additive shares over a number of rounds.

This document is structured as follows.

* {{daf}} defines Distributed Aggregation Functions (DAFs), which distribute the
  computation of an aggregation function among a set of aggregators in order to
  keep the inputs private.

* {{vdaf}} defines Verifiable Distributed Aggregation Functions (VDAFs), an
  extension of DAFs that additionally allow the aggregators to detect malformed
  inputs.

* {{prio3}} specifies a VDAF suitable for the use cases of the original Prio
  system [CGB17].

* {{hits}} specifies a VDAF for an "Incremental Distributed Point Function
  (IDPF)" for which the aggregators verify the output at each level of the tree.
  This corresponds to the protocol for the subset-histogram problem described by
  [BBCGGI21].

* {{coins}} defines a procedure for negotiating shared randomness used by the
  verifiers.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

Algorithms are written in Python 3. Unless noted otherwise, function parameters
without a type hint implicitly have type `Bytes`, an arbitrary byte string. A
fatal error in a program (e.g., failure to parse one of the function parameters)
is usually handled by raising an exception.

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

# Verifiable Distributed Aggregation Functions {#vdaf}

~~~~
client
  | input
  v
+-----------------------------------------------------------+
| vdaf_input()                                              |
+-----------------------------------------------------------+
  | input_shares[1]  | input_shares[2]   ...  | input_shares[SHARES]
  v                  v                        v
+---------------+  +---------------+        +---------------+
| vdaf_start()  |  | vdaf_start()  |        | vdaf_start()  |
+---------------+  +---------------+        +---------------+
  |                  |                   ...  |
  =============================================
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| vdaf_next()   |  | vdaf_next()   |        | vdaf_next()   |
+---------------+  +---------------+        +---------------+
  |                  |                   ...  |
  =============================================
  |                  |                        |
  v                  v                        v
  .                  .                        .
  .                  .                        .
  .                  .                        .
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| vdaf_finish() |  | vdaf_finish() |        | vdaf_finish() |
+---------------+  +---------------+        +---------------+
  | output_shares[1] | output_shares[2]  ...  | output_shares[SHARES]
  v                  v                        v
aggregator 1       aggregator 2             aggregator SHARES
~~~~
{: #vdaf-flow title="Execution of a VDAF. The === line represents a broadcast
channel."}

The main limitation of DAF schemes is that, because each aggregator only holds a
piece of the distributed input, there is no way for them to check that the
output is valid. A VDAF is an extension of a DAF in which the aggregators verify
that the output is valid before recovering their output shares, without leaking
their shares to the other aggregators. Doing so requires the aggregators to
interact with one another, which they do over a broadcast channel.

Execution of a VDAF is illustrated in {{vdaf-flow}}. It begins just as before
(see {{daf-flow}}) by having the client run the input-distribution algorithm and
send an input share to each of the aggregators. The aggregators then proceed in
a constant number of rounds, where in each round, each aggregator produces a
single outbound message. The outbound messages are written to a broadcast
channel, which transmits all of the messages to each aggregator in the next
round. Eventually, each aggregator decides if the input shares are valid based
on its view of the protocol. If so, it returns an output share. Otherwise it
returns an indication of invalidity.

Syntactically, a VDAF is made up of the following algorithms:

* `vdaf_setup() -> (public_param, verify_param)` is the setup algorithm used to
  generate the public parameter used by the client (`public_param`) and the
  verification parameter used by the aggregators (`verify_param`). The
  parameters are generated once and reused across multiple VDAF evaluations. The
  verification parameter MUST NOT be revealed to the clients.

* `vdaf_input(public_param, input) -> input_shares: Vec[Vec[bytes]]` is the
  input-distribution algorithm run by the client. It consumes the public
  parameter and input produces a sequence of input shares, one for each
  aggregator (i.e., `len(input_shares) == SHARES`).

* `vdaf_start(verify_param, agg_param, nonce, input_share) -> (state: State,
  outbound_message)` is the verify-start algorithm and is run by each
  aggregator. Its inputs are the verification parameter (`verify_param`), the
  aggregation parameter (`agg_param`), the nonce provided by the environment
  (`nonce`; see {{run-vdaf}}), and one of the input shares generated by the
  client (`input_share`). Its outputs include the aggregator's initial state
  (`state`) and the outbound message it sends in the first round
  (`outbound_message`).

    [NOTE The nonce is provided by the environment, i.e., is generated by the
    PPM wrapper protocol. We need to change the spec to make this 16 bytes to
    avoid collisions.]

* `vdaf_next(state: State, inbound_messages: Vec[bytes]) -> (new_state: State,
  outbound_message)` is the verify-next algorithm. For each round `i >= 2` it
  consumes the `(i-1)`-th round of inbound messages (note that
  `len(inbound_messages) == SHARES`) and produces the aggregator's `i`-th
  outbound message. This algorithm is undefined if `ROUNDS == 1`.

* `vdaf_finish(state: State, inbound_messages: Vec[bytes]) -> output_share` is
  the verify-finish algorithm. It consumes the last round of inbound messages
  (note that `len(inbound_messages) == SHARES`) and produces the aggregator's
  output share.

    [TODO For heavy hitters, is the aggregation parameter rquired by the
    verify-start algorithm, or can it be passed in to the verify-finish
    algorithm here? If the latter is possible, then there would be no need to
    wait for the collect request to start validating inputs.]

Associated types:

* `State` is the state of an aggregator during executing of the VDAF. The type
  is defined by the VDAF itself.

Associated constants:

* `SHARES: Unsigned` is the number of aggregators for which the VDAF is defined.
* `ROUNDS: Unsigned` is the number of rounds of communication between the
  aggregators.

Just as for DAF schemes, we require that for each aggregation parameter
`agg_param`, the set of output shares `G(agg_param)` forms an additive group.
The aggregation function is computed by running the VDAF as specified below (let
`Zero(agg_param)` denote the additive identity of `G(agg_param)`):

~~~
def run_vdaf(agg_param, inputs: Set[bytes]):
  output_shares = [ Zero(agg_param) for _ in range(SHARES) ]

  (public_param, verify_param) = vdaf_setup()

  for input in inputs:
    # Each client runs the input-distribution algorithm.
    input_shares = vdaf_input(public_param, input)

    # The environment generates the next nonce.
    nonce = nonce_gen()

    # Aggregators recover their output shares.
    outbound, states = [], []
    for j in range(SHARES):
      (state, msg) = vdaf_start(
          verify_param, agg_param, nonce, input_shares[j])
      outbound.append(msg); states.append(state)
    inbound = outbound

    for i in range(ROUNDS-1):
      for j in range(SHARES):
        (states[j], outbound[j]) = vdaf_next(states[j], inbound)
      inbound = outbound

    for j in range(SHARES):
      output_share[j] += vdaf_finish(states[j], inbound)

  # Aggregators compute the final output.
  return sum(output_shares)
~~~
{: #run-vdaf title="Execution of a VDAF. The environment provides secure
point-to-point connections, a broadcast channel, and a unique nonce for each
VDAF evaluation."}

NOTE Algorithm `run_vdaf` specifies the environment in which the VDAF is
expected to be evaluated. In particular, it provides generation of a unique
nonce for each VDAF evaluation and a secure broadcast channel for executing each
round of the protocol. In practice, this environment is "simulated" by the PPM
protocol.

# [Working name] prio3 {#prio3}

NOTE This is WIP.

NOTE This protocol has not undergone significant security analysis. This is
planned for [PAPER].

The etymology of the term "prio3" is that it descends from the original Prio
construction [CGB17], which was deployed in Firefox's origin telemetry project
(i.e., "prio1"). It generalizes the more recent deployment in the ENPA system
(i.e., "prio2") and is based on techniques described in [BBDGGI19].

## Dependencies

### Fully Linear, Probabilistically Checkable Proof

NOTE [BBDGGI19] call this a 1.5-round, public-coin, interactive oracle proof
system.

All raise `ERR_INPUT`:

* `pcp_prove(input: Vec[Field], prove_rand: Vec[Field], joint_rand: Vec[Field]) ->
  proof: Vec[Field]` is the proof-generation algorithm.
* `pcp_query(input: Vec[Field], proof: Vec[Field], query_rand: Vec[Field],
  joint_rand: Vec[Field]) -> verifier: Vec[Field]` is the query-generation
  algorithm.
* `pcp_decide(verifier: Vec[Field]) -> decision: Boolean` is the decision algorithm.

Associated types

* `Field`
  Associated functions:

  * `vec_rand(len: U32) -> output: Vec[Field]` require that `len == len(output)`
  * `vec_zeros(len: U32) -> output: Vec[Field]` require that `len ==
    len(output)` and each element of `output` is zero.
  * `encode_vec`
  * `decode_vec` raises `ERR_DECODE`

  Associated constants:

  * `ENCODED_SIZE`

Associated constants:

* `JOINT_RAND_LEN`
* `PROVE_RAND_LEN`
* `QUERY_RAND_LEN`

Execution semantics:

~~~
def run_pcp(input: Vec[Field]):
  joint_rand = vec_rand(JOINT_RAND_LEN)
  prove_rand = vec_rand(PROVE_RAND_LEN)
  query_rand = vec_rand(QUERY_RAND_LEN)

  # Prover generates the proof.
  proof = pcp_prove(input, prove_rand, joint_rand)

  # Verifier queries the input and proof.
  verifier = pcp_query(input, proof, query_rand, joint_rand)

  # Verifier decides if the input is valid.
  return pcp_decide(verifier)
~~~
{: #run-pcp title="Execution of a fully linear PCP."}


### Key Derivation

[TODO Separate this syntax from what people usually think of as a KDF.] A
key-derivation scheme consists of the following algorithms:

* `get_key(init_key, input) -> key` require `len(init_key) == KEY_SIZE` and
  `len(key) == KEY_SIZE`.
* `get_key_stream(key) -> state: KeyStream` require that `len(key) == KEY_SIZE`.
* `key_stream_next(state: KeyStream, length: U32) -> (new_state: KeyStream,
  output)` require that `length == len(output)`

Associated types:

* `KeyStream`

Associated constants:

* `KEY_SIZE`

## Construction

~~~
def vdaf_setup():
  k_query_init = get_rand(KEY_SIZE)
  return (bytes(), k_query_init)
~~~
{: #prio3-vdaf-setup title="The setup algorithm for prio3."}

~~~
def vdaf_input(_, r_input):
  input = decode_vec(r_input)
  k_joint_rand = zeros(SEED_SIZE)

  # Generate input shares.
  leader_input_share = input
  k_helper_input_shares = []
  k_helper_blinds = []
  k_helper_hints = []
  for j in range(SHARES-1):
    k_blind = get_rand(KEY_SIZE)
    k_share = get_rand(KEY_SIZE)
    helper_input_share = expand(k_share, len(leader_input_share))
    leader_input_share -= helper_input_share
    k_hint = get_key(k_blind,
        byte(j+1) + encode_vec(helper_input_share))
    k_joint_rand ^= k_hint
    k_helper_input_shares.append(k_share)
    k_helper_blinds.append(k_blind)
    k_helper_hints.append(k_hint)
  k_leader_blind = get_rand(KEY_SIZE)
  k_leader_hint = get_key(k_leader_blind,
      byte(0) + encode_vec(leader_input_share))
  k_joint_rand ^= k_leader_hint

  # Finish joint randomness hints.
  for j in range(SHARES-1):
    k_helper_hints[i] ^= k_joint_rand
  k_leader_hint ^= k_joint_rand

  # Generate the proof shares.
  joint_rand = expand(k_joint_rand, JOINT_RAND_LEN)
  prove_rand = expand(get_rand(KEY_SIZE), PROVE_RAND_LEN)
  leader_proof_share = pcp_prove(input, prove_rand, joint_rand)
  k_helper_proof_shares = []
  for j in range(SHARES-1):
    k_share = get_rand(KEY_SIZE)
    k_helper_proof_shares.append(k_share)
    helper_proof_share = expand(k_share, len(leader_proof_share))
    leader_proof_share -= helper_proof_share

  output = []
  output.append(encode_leader_share(0,
    leader_input_share,
    leader_proof_share,
    k_leader_blind,
    k_leader_hint,
  ))
  for j in range(SHARES-1):
    output.append(encode_helper_share(j,
      (k_helper_input_share[j], len(leader_input_share)),
      (k_helper_proof_share[j], len(leader_proof_share)),
      k_helper_blinds[j],
      k_helper_hints[j],
    ))
  return output
~~~
{: #prio3-vdaf-input title="Input distribution algorithm for prio3. TODO
Figure out how this looks in the normal text format."}

~~~
def vdaf_start(k_query_init, _, nonce, r_input_share):
  (j, input_share, proof_share,
   k_blind, k_hint) = decode_share(input_share)
  if j > 0: # helper
    input_share = expand(*input_share)
    proof_share = expand(*proof_share)

  k_joint_rand_share = get_key(k_blind, byte(j) + input_share)
  k_joint_rand = k_hint ^ k_joint_rand_share
  k_query_rand = get_key(k_query_init, byte(255) + nonce)

  joint_rand = expand(k_joint_rand, JOINT_RAND_LEN)
  query_rand = expand(k_query_rand, QUERY_RAND_LEN)
  verifier_share = pcp_query(
      input_share, proof_share, query_rand, joint_rand)
  verifier_length = len(verifier_share)

  state = encode_state(k_joint_rand, input_share, verifier_length)
  output = encode_verifier_share(k_joint_rand, verifier_share)
  return (state, output)
~~~
{: #prio3-vdaf-start title="Verify-start algorithm for prio3."}

`ROUNDS` is 1 for Prio3, and so no `vdaf_next` definition is provided.

~~~
def vdaf_finish(state: State, r_verifier_shares):
  if len(r_verifier_shares) != s: raise ERR_DECODE

  k_joint_rand = zeros(KEY_SIZE)
  verifier = vec_zeros(state.verifier_len)
  for r_share in r_verifier_shares:
    (k_joint_rand_share,
     verifier_share) = decode_verifier_share(r_share)
    if len(verifier_share) != state.verifier_length:
      raise ERR_DECODE

    k_joint_rand ^= k_joint_rand_share
    verifer += verifier_share

  if k_joint_rand != state.k_joint_rand: raise ERR_INVALID
  if not pcp_decide(verifier): raise ERR_INVALID
  return state.input_share
~~~
{: #prio3-vdaf-finish title="Verify-finish algorithm for prio3."}

Auxiliary functions:

* `expand(seed, length: U32) -> output: Vec[Field]`
* `encode_state`
* `encode_helper_share`
* `encode_leader_share`
* `decode_share` raises `ERR_DECODE`
* `encode_verifier_share`
* `decode_verifier_share` raises `ERR_DECODE`
* `get_rand(length: U32) -> output` require that `length == len(output)`
* `zeros(length: U32) -> output` require that `lengh == len(output)` and that
  each element of `output` is zero.

NOTE `JOINT_RAND_LEN` may be `0`, in which case the joint randomness computation
is not necessary. Should we bake this option into the spec?


# [Working name] hits {#hits}

TODO

* Input is a bit string of a specific length.
* Input shares are IDPF shares and the correlated randomness for each level of
  the tree.
* Aggregation parameter is a set of candidate prefixes, all having the same
  length.
* Output shares are secret shares of a vector of field elements, each
  corresponding to a counter for one of the candidate prefixes.


# Negotiating Verification Parameters {#coins}

TODO The setup algorithm often involves generating and distributing randomness
used by the aggregators for verification. This section will describer a generic
protocol for securely accomplishing this task.


# Security Considerations

TODO There will be a companion paper [PAPER] that will formalize the syntax and
security of VDAFs and analyze some of the constructions specified here. Here we
will say at a high level what completeness, soundness, and privacy (i.e.,
zero-knowledge) are.

Things that are out of scope:

* Sybil attacks [Dou02]

* Differential privacy [Vad16]

* VDAF is expected to be run in the ideal environment specified in {{run-vdaf}}.
  In particular, standard network attackers that can drop messages or inject
  messages at will are out-of-scope. Such attackers are considered in the
  PPM protocol, which is designed to "simulate" the environment expected by the
  VDAF.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

Thanks to Henry Corrigan-Gibbs and Christopher Wood for useful feedback on the
syntax of VDAF schemes.
