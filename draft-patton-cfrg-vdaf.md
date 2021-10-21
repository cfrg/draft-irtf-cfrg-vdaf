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

  BBCGGI19:
    title: "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    seriesinfo: CRYPTO 2019
    date: 2019

  BBCGGI21:
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

  EPK14:
    title: "RAPPOR: Randomized Aggregatable Privacy-Preserving Ordinal Response"
    author:
      - ins: Ú. Erlingsson
      - ins: V. Pihur
      - ins: A. Korolova
    seriesinfo: CCS 2014
    date: 2014
    target: "https://dl.acm.org/doi/10.1145/2660267.2660348"

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

  Dwo06:
    title: "Differential Privacy"
    date: 2006
    seriesinfo: "ICALP 2006"
    target: "https://link.springer.com/chapter/10.1007/11787006_1"

  PPM:
    title: "Privacy Preserving Measurement"
    date: 2021
    author:
      - ins: T. Geoghagen
      - ins: C. Patton
      - ins: E. Rescorla
      - ins: C. Wood

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
servers to detect if a malicious (or merely misconfigured) client submitted an
input that would result in the output getting garbled.


--- middle

# Introduction

The ubiquity of the Internet makes it an ideal platform for measurement of
large-scale phenomena, whether public health trends or the behavior of computer
systems at scale. There is some overlap, however, between information that is
valuable to measure and information that users consider private.

For example, consider an application that provides health information to users.
The operator of an application might want to know which parts of their
application are used most often, as a way to guide future development of the
application.  A particular user's pattern of usage, though, could reveal
sensitive things about them.

In many situations, the measurement collector is only interested in aggregate
statistics, e.g., which portions of an application are most used or what
fraction of people have experienced a given disease.  Thus systems that provide
aggregate statistics while protecting individual measurements can deliver the
value of the measurements while protecting users' privacy.

Most prior approaches to this problem fall under the rubric of "differential
privacy (DP)" [Dwo06]. Roughly speaking, a data aggregation system that is
differentially private ensures that the degree to which any individual
measurement influences the value of the aggregated output can be controlled.
For example, in systems like RAPPOR [EPK14], each user samples noise from a
well-known distribution and adds it to their input before submitting to the
aggregation server. The aggregation server then adds up the noisy inputs, and
because it knows the distribution of the noise, it can accurately estimate the
true sum with reasonable precision.

Systems like RAPPOR are practical and provide a useful privacy property (DP). On
its own, however, DP falls short of the strongest privacy property one could
hope for. Specifically, depending on the "amount" of noise a client adds to its
input, it may be possible for a curious aggregator to make a reasonable guess of
the input's true value. Indeed, the amount of noise added needs to be carefully
controlled, since the more noise that is added to inputs, the less reliable will
be the estimate of the output. Thus systems employing DP techniques alone must
strike a delicate balance between privacy and utility.

The ideal goal for a privacy-preserving measurement system is that of secure
multi-party computation: No participant in the protocol should learn anything
about an individual input beyond what it can deduce from the final output.
In this document, we describe Verifiable Distributed Aggregation Functions
(VDAFs) as a general class of protocols that achieve this goal by distributing
trust among a number of non-colluding aggregation servers. Privacy is achieved
as long as a subset of the servers executes the protocol honestly. At the same
time, VDAFs are "verifiable" in the sense that malformed inputs that would
otherwise garble the output of the computation can be detected and removed from
the set of inputs. The cost of these benefits is the need for multiple servers
to participate in the protocol, and the need to ensure they do not collude to
undermine the VDAF's privacy guarantees.

The VDAF abstraction, presented in {{vdaf}}, is based on a variety of
multi-party protocols for privacy-preserving measurement that have been proposed
in the literature in recent years. These protocols vary in their operational and
security considerations in (often) subtle ways. Thus the primary goal of this
document is to specify these considerations and provide a unified abstraction
that gives cryptographers design criteria for new constructions. This document's
considerations are derived from the concurrent effort to standardize a protocol
for privacy-preserving measurement in [PPM].

This document also specifies two concrete VDAF schemes, each based on a protocol
from the literature.

* Prio [CGB17] is a scheme proposed by Corrigan-Gibbs and Boneh in 2017 that
  allows for the privacy-preserving computation of a variety aggregate
  statistics. Each input is split into a sequence of additive input shares and
  distributed among the aggregation servers. Each server then adds up its inputs
  shares locally. Finally, the output is obtained by combining the servers'
  local output shares. Prio also specifies a multi-party computation for
  verifying the validity of the input shares, where validity is defined by an
  arithmetic circuit evaluated over the input.

  In {{prio3}} we describe `prio3`, a VDAF that permits the same uses cases as
  the original Prio protocol, but which is based on cryptographic techniques
  introduced later in [BBCGGI19] that result in significant performance gains.

* More recently, Boneh et al. [BBCGGI21] described a protocol for solving the
  `t`-heavy-hitters problem in a privacy-preserving manner. In this setting,
  each client holds a bit-string of length `n`, and the goal of the aggregation
  servers is to compute the set of inputs that occur at least `t` times. The
  core primitive used in their protocol is a generalization of a Distributed
  Point Function (DPF) [GI14] that allows the servers to "query" their DPF
  shares on any bit-string of length shorter than or equal to `n`. As a result
  of this query, each of the servers has an additive share of a bit indicating
  whether the string is a prefix of the client's input. The protocol also
  specifies a multi-party computation for verifying that at most one string
  among a set of candidates is a prefix of the client's input.

  In {{hits}} we describe a VDAF called `hits` that captures this functionality.

The remainder of this document is organized as follows. {{overview}} gives a
brief overview of VDAFs and the environment in which they are expected to run;
{{vdaf}} specifies the syntax for VDAFs; {{prio3}} describes `prio3`; {{hits}}
describes `hits`; and {{security}} enumerates the security considerations for
VDAFs.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Algorithms are written in Python 3. Unless noted otherwise, function parameters
without a type hint implicitly have type `Bytes`, an arbitrary byte string. A
fatal error in a program (e.g., failure to parse one of the function parameters)
is usually handled by raising an exception.

# Overview {#overview}

TODO

## VDAFs in the Literature

The VDAF primitive is intended to unify into one abstraction the core
cryptographic functionalities of a wide variety of privacy-preserving protocols
in the literature. This section enumerates these protocols.

## Prio

While not the first protocol in this class of protocols, Prio [CGB17] is the
protocol that inspired this standardization effort.

TODO

## Privacy-preserving Heavy Hitters

TODO [BBCGGI21]


# Definition {#vdaf}

A concrete VDAF specifies the algorithms involved in evaluating the VDAF on a
single input and the algorithms involved in aggregating the outputs of multiple
evaluations. This section specifies the interfaces of these algorithms as they
would be exposed to applications.

In addition to these algorithms, a concrete VDAF specifies the following
constants:

* `SHARES: Unsigned` is the number of aggregators for which the VDAF is defined.
* `ROUNDS: Unsigned` is the number of rounds of communication executed by the
  aggregators during VDAF evaluation.

The VDAF also specifies the following associated types:

* `EvalState` is the state of an aggregator VDAF evaluation of a single input.
* `AggState` is the aggregation state used across VDAF evaluations.

## Input-Evaluation Phase

~~~~
client
  | input
  v
+-----------------------------------------------------------+
| eval_input()                                              |
+-----------------------------------------------------------+
  | input_shares[1]  | input_shares[2]   ...  | input_shares[SHARES]
  v                  v                        v
+---------------+  +---------------+        +---------------+
| eval_start()  |  | eval_start()  |        | eval_start()  |
+---------------+  +---------------+        +---------------+
  |                  |                   ...  |
  =============================================
  |                  |                        |
  v                  v                        v
+---------------+  +---------------+        +---------------+
| eval_next()   |  | eval_next()   |        | eval_next()   |
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
| eval_finish() |  | eval_finish() |        | eval_finish() |
+---------------+  +---------------+        +---------------+
  | output_shares[1] | output_shares[2]  ...  | output_shares[SHARES]
  v                  v                        v
aggregator 1       aggregator 2             aggregator SHARES
~~~~
{: #eval-flow title="Evaluation of a VDAF on a single input. The aggregators
communicate over a broadcast channel illustrated by the === line. At the end of
the protocol, each aggregator has recovered a share of the output."}

The evaluation phase of the VDAF is illustrated in {{eval-flow}}. It begins by
having the client split its input into a sequence of input shares and sending
each input share to one of the aggregators. The aggregators then interact with
one another over a number of rounds, where in each round, each aggregator
produces a single outbound message. The outbound messages are broadcast to all
of the aggregators at the beginning of each round. Eventually, each aggregator
recovers a share of the output. Evaluation of the VDAF involves the following
algorithms:

* `eval_setup() -> (public_param, verify_params: Vec[Bytes])` is the randomized
  setup algorithm used to generate the public parameter used by the clients
  (`public_param`) and the verification parameters used by the aggregators
  (`verify_params`, note that `len(input_shares) == SHARES`). The parameters are
  generated once and reused across multiple VDAF evaluations. The verification
  parameter MUST NOT be revealed to the clients.

* `eval_input(public_param, input) -> input_shares: Vec[Bytes]` is the
  input-distribution algorithm run by the client. It consumes the public
  parameter and input measurement and produces a sequence of input shares, one
  for each aggregator (i.e., `len(input_shares) == SHARES`).

* `eval_start(verify_param, agg_param, nonce, input_share) -> (state: EvalState,
  outbound_message)` is the verify-start algorithm and is run by each
  aggregator. Its inputs are the aggregator's verification parameter
  (`verify_param`), the aggregation parameter (`agg_param`), the nonce provided
  by the environment (`nonce`, see {{run-vdaf}}), and one of the input shares
  generated by the client (`input_share`). Its outputs include the aggregator's
  initial state (`state`) and its round-`1` verification message
  (`outbound_message`).

* `eval_next(state: EvalState, inbound_messages: Vec[Bytes]) -> (new_state:
  EvalState, outbound_message)` is the verify-next algorithm. For each round `i
  >= 2` it consumes the round-`(i-1)` messages (note that `len(inbound_messages)
  == SHARES`) and produces the aggregator's round-`i` message. This algorithm is
  undefined if `ROUNDS < 2`.

* `eval_finish(state: EvalState, inbound_messages: Vec[Bytes]) -> output_share`
  is the verify-finish algorithm. It consumes the round-`ROUNDS` verification
  messages (note that `len(inbound_messages) == SHARES`) and produces the
  aggregator's output share. Raises an exception if a valid output share could
  not be recovered.

## Output-Aggregation Phase

Aggregation of VDAF outputs happens concurrently with the evaluation of the VDAF
on individual inputs. Once an aggregator has recovered a valid output share, it
adds it into its long-running aggregation state locally. Once all of the inputs
have been processed, the aggregators combine their aggregate shares into the
final aggregate. This process involves the following algorithms:

* `agg_start() -> AggState` is the deterministic aggregation-state
  initialization algorithm. It is run by each aggregator before processing any
  client input shares.

* `agg_next(state: AggState, output_share) -> new_state: AggState` is the
  deterministic aggregation-state update algorithm. It is run immediately after
  the aggregator recovers a valid output share `output_share`.

* `agg_finish(states: Vec[AggStates]) -> agg` combines the aggregation state
  of each aggregator (note that `len(states) == SHARES`) into the final
  aggregate `agg`.

## Execution Model {#execution}

Executing a VDAF involves the concurrent evaluation of the VDAF on individual
inputs and aggregation of the outputs of each evaluation. This is captured by
the following algorithm:

~~~
def run_vdaf(agg_param, nonces: Vec[Bytes], inputs: Vec[Bytes]):
  # Distribute long-lived evaluation parameters.
  (public_param, verify_params) = eval_setup()

  # Each aggregator initializes its aggregation state.
  agg = [ agg_start() for j in range(SHARES) ]

  for (nonce, input) in zip(nonces, inputs):
    # Each client runs the input-distribution algorithm.
    input_shares = eval_input(public_param, input)

    # Aggregators recover their output shares.
    outbound, eval = [], []
    for j in range(SHARES):
      (state, msg) = eval_start(
          verify_params[j], agg_param, nonce, input_shares[j])
      outbound.append(msg); eval.append(state)
    inbound = outbound

    for i in range(ROUNDS-1):
      for j in range(SHARES):
        (eval[j], outbound[j]) = eval_next(eval[j], inbound)
      inbound = outbound

    for j in range(SHARES):
      output_share = eval_finish(eval[j], inbound)
      agg[j] = agg_next(agg[j], output_share)

  # Aggregators compute the final output.
  return agg_finish(agg)
~~~
{: #run-vdaf title="Execution of a VDAF."}

The inputs to this algorithm are the aggregation parameter `agg_param`, a set of
nonces `nonces`, and a set of inputs `inputs`. The aggregation parameter is
chosen by the aggregators prior to executing the VDAF and the inputs are chosen
by the clients. This document does not specify how the nonces are chosen, but
some of our security considerations require that the nonces be unique for each
VDAF evaluation. See {{security}} for details.

Another important question this document leaves out of scope is how a VDAF is to
be executed by aggregators distributed over a real network. Algorithm `run_vdaf`
prescribes the protocol's execution in a "benign" environment in which there is
no adversary and messages are passed among the protocol participants over secure
point-to-point channels. In reality, these channels need to be instantiated by
some "wrapper protocol" that implements suitable cryptographic functionalities.
Moreover, some fraction of the aggregators (or clients) may be malicious and
diverge from their prescribed behaviors. {{security}} describes the execution of
the VDAF in various adversarial environments what properties the wrapper
protocol needs to provide.

<!--
## VDAFs in the Literature

TODO

* Prio [CGB17] defines the composition of a linear secret sharing scheme and an
  affine-aggregatable encoding of a statistic.

* A special case of zero-knowledge proofs over distributed data [BBCGGI19] in
  which the client speaks once.

* The composition of an incremental distributed point function and the
  secure-sketching protocol for subset histograms defined in [BBCGGI21].

* Prio+ [AGJOP21] has the client upload XOR shares and then has the servers
  convert them to additive shares over a number of rounds.
-->

# prio3 {#prio3}

NOTE This is WIP.

NOTE This protocol has not undergone significant security analysis. This is
planned for [PAPER].

The etymology of the term "prio3" is that it descends from the original Prio
construction [CGB17], which was deployed in Firefox's origin telemetry project
(i.e., "prio1"). It generalizes the more recent deployment in the ENPA system
(i.e., "prio2") and is based on techniques described in [BBCGGI19].

## Dependencies

### Fully Linear, Probabilistically Checkable Proof

NOTE [BBCGGI19] call this a 1.5-round, public-coin, interactive oracle proof
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


# Security Considerations {#security}

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
