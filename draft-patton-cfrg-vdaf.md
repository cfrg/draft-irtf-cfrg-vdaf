---
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
    email: cpatton@cloudflare.com

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
input that would result in the aggregate getting garbled.

--- middle

# Introduction

> TODO Clean up references

> TODO Harmonize author comment convention

> TODO Finish prio3 (sans concrete PCP)

> TODO Finish hits (sans concrete IDPF)

> TODO Finish security considerations

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
because it knows the distribution from whence the noise was sampled, it can
accurately estimate the true sum with reasonable precision.

Systems like RAPPOR are easy to deploy and provide a useful privacy property
(DP). On its own, however, DP falls short of the strongest privacy property one
could hope for. Specifically, depending on the "amount" of noise a client adds
to its input, it may be possible for a curious aggregator to make a reasonable
guess of the input's true value. Indeed, the amount of noise needs to be
carefully controlled, since the more noise that is added to inputs, the less
reliable will be the estimate of the output. Thus systems employing DP
techniques alone must strike a delicate balance between privacy and utility.

The ideal goal for a privacy-preserving measurement system is that of secure
multi-party computation: No participant in the protocol should learn anything
about an individual input beyond what it can deduce from the aggregate. In this
document, we describe Verifiable Distributed Aggregation Functions (VDAFs) as a
general class of protocols that achieve this goal.

VDAF schemes achieves their privacy goal by distributing the computation of the
aggregate among a number of non-colluding aggregation servers. As long as a
subset of the servers executes the protocol honestly, VDAFs guarantee that no
input is ever visible in the clear. At the same time, VDAFs are "verifiable" in
the sense that malformed inputs that would otherwise garble the output of the
computation can be detected and removed from the set of inputs.

The cost of achieving these security properties is the need for multiple servers
to participate in the protocol, and the need to ensure they do not collude to
undermine the VDAF's privacy guarantees. However, recent implementation
experience has shown that deployment of these schemes is practical.

> TODO Decide what to say about ENPA or Mozilla's Origin Telemetry.

The VDAF abstraction, presented in {{vdaf}}, is based on a variety of
multi-party protocols for privacy-preserving measurement proposed in the
literature. These protocols vary in their operational and security
considerations, sometimes in subtle, but consequential, ways. This document
therefore has two important goals:

 1. Specify the operational and security considerations for this class of
    protocols, including:

    1. Which communication patterns are feasible, i.e., how much interaction
       between the client and aggregation servers is feasible, how and how much
       the aggregation servers ineteract amongst themselves, and so on.
    1. What are the capabilities of a malicious coalition of servers attempting
       divulge information about client inputs.
    1. What conditions are necessary to ensure that a malicious coalition of
       clients cannot corrupt the computation.

 1. Define an abstraction boundary that provides applications, like [PPM], with
    a simple, uniform interface for accessing privacy-preserving measurement
    schemes, while also providing cryptographers with design criteria for new
    constructions.

This document also specifies two concrete VDAF schemes, each based on a protocol
from the literature.

* Prio [CGB17] is a scheme proposed by Corrigan-Gibbs and Boneh in 2017 that
  allows for the privacy-preserving computation of a variety aggregate
  statistics. The input is sharded into a sequence of additive input shares and
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
brief overview of VDAFs; {{vdaf}} defines the syntax for VDAFs; {{prio3}}
describes `prio3`; {{hits}} describes `hits`; and {{security}} enumerates the
security considerations for VDAFs.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Algorithms are written in Python 3. Function parameters without a type hint
implicitly have type `Bytes`, an arbitrary byte string. A fatal error in a
program (e.g., failure to parse one of the function parameters) is usually
handled by raising an exception.

Some common functionalities:

* `zeros(len: Unsigned) -> output: Bytes` returns an array of bytes of length
  `len` (i.e., it is required that `len(output) == len`).

* `gen_rand(len: Unsigned) -> output: Bytes` returns an array of `len` random
  bytes (i.e., it is required that `len(output) == len`).

# Overview {#overview}

In a private measurement system, we distinguish three types of actors: Clients,
Aggregators, and Collectors.  The overall flow of the measurement process is as
follows:

* Clients are configured with public parameters for a set of Aggregators.
* To submit an individual measurement, a Client shards the measurement into
  "input shares" and sends one input share to each Aggregator.
* The Aggregators accept these submissions and group individual measurements
  into batches over which the desired aggregate statistics will be computed.

    > CP I don't think the notion of "batch" is central to VDAFs. I think our
    > overview would be cleaner if we just said that there is a set of inptus
    > over which we want to compute some aggregate statistic.

  For each batch, the Aggregators:
  * Validate that the individual measurements in the batch meet the requirements
    of the system.
  * Combine the input shares into "output shares" of the desired aggregate.

      > CP This isn't quite right. It's more accurate to say: The Aggregators
      > want to compute some function of the input -- call it the "aggregation
      > function" -- and we want that each Aggregator only holds a share of the
      > input and only gets a share of the output. (To be clear: Outputs from
      > multiple evaluations of this function care combined to get the final
      > aggregate.)

* According to the needs of the particular VDAF, Aggregators may need to
  exchange information among themselves as part of the validation and
  aggregation process.

    > CP What does this mean? To my read, this statement imply that, depending
    > on the VDAF, interaction may not be necessary in order to verify output
    > share validity.

* The Aggregators submit their output shares to the Collector, who combines them
  to obtain the aggregate result over the batch.

~~~
                 +--------------+
           +---->| Aggregator 0 |----+
           |     +--------------+    |
           |             ^           |
           |             |           |
           |             V           |
           |     +--------------+    |
           | +-->| Aggregator 1 |--+ |
           | |   +--------------+  | |
+--------+-+ |           ^         | +->+-----------+
| Client |---+           |         +--->| Collector |--> Aggregate
+--------+-+                         +->+-----------+
           |            ...          |
           |                         |
           |             |           |
           |             V           |
           |    +----------------+   |
           +--->| Aggregator N-1 |---+
                +----------------+

          Input shares                Output Shares
~~~
{: #overall-flow title="Overall data flow of a VDAF"}

> CP Note that I changed this caption to talk specifically about VDAFs rather
> than generally about private measurement systems. Systems like RAPPOR have a
> different data flow.

Aggregators are a new class of actor relative to traditional measurement systems
where clients submit measurements to a single server.  They are critical for
both the privacy properties of the system and the correctness of the
measurements obtained.  The privacy properties of the system are assured by
non-collusion among aggregators, and aggregators are the entities that perform
validation of client inputs.  Thus clients trust aggregators not to collude and
collectors trust aggregators to properly verify client inputs.

Within the bounds of the non-collusion requirements of a given VDAF instance --
privacy requires that a subset of the Aggregators (typically just one) is honest
-- it is possible for the same entity to play more than one role.  For example,
the Collector could also act as an Aggregator, effectively using the other
Aggregators to augment a basic client-server protocol.  It is even possible to
have a fully democratic system, where each participant acts as Client,
Aggregator, and Collector -- allowing a group of participants to agree on an
aggregate over a set of measurements without any participant learning anything
about other participants' measurements.

In this document, we describe the computations performed by the actors in this
system.  It is up to applications to arrange for the required information to be
delivered to the proper actors in the proper sequence.  In general, we assume
that all communications are confidential and mutually authenticated, with the
exception that Clients submitting measurements may be anonymous.

# Definition of VDAFs {#vdaf}

A concrete VDAF specifies the algorithms involved in evaluating the VDAF on a
single input and the algorithms involved in aggregating the outputs across
multiple evaluations into the final aggregate. This section specifies the
interfaces of these algorithms as they would be exposed to applications.

A concrete VDAF scheme specifies implementations of these algorithm. In
addition, a VDAF specifies the following constants:

* `SHARES: Unsigned` is the number of Aggregators for which the VDAF is defined.
* `ROUNDS: Unsigned` is the number of rounds of communication among the
  Aggregators before they recover output shares from a single set of input
  shares.

A concrete VDAF also specifies the following associated types:

* `EvalState` is the state of an Aggregator during evaluation of a single Client input.
* `AggState` is the state of an Aggregator carried across multiple evaluations.

## Input Evaluation

~~~~
    Client
      |
      V
    +---------------------------------------------+
    | eval_input                                  |
    +---------------------------------------------+
      |              |              ...  |
      V              V                   V
    +-----------+  +-----------+       +-----------+
    | eval_init |  | eval_init |       | eval_init |
    +-----------+  +------------+      +-----------+
      |              |              ...  |
      V              V                   V
    +-----------+  +-----------+       +-----------+
    | eval_next |  | eval_next |       | eval_next |
    +-----------+  +-----------+       +-----------+
      |              |              ...  |
      ====================================
      |              |                   |
      V              V                   V
     ...            ...                 ...
      |              |                   |
      V              V                   V
    +-----------+  +-----------+       +-----------+
    | eval_next |  | eval_next |       | eval_next |
    +-----------+  +-----------+       +-----------+
      |              |              ...  |
      V              V                   V
    Aggregator 0   Aggregator 1        Aggregator SHARES-1
~~~~
{: #eval-flow title="Evaluation of the VDAF on a single input. The Aggregators
communicate over a broadcast channel, illustrated by the === line. At the end of
the protocol, each Aggregator has recovered a share of the output."}

Input evaluation involves a Client and the Aggregators. The process, illustrated
in {{eval-flow}}, begins by having the Client shard its input into a sequence of
input shares and sending each input share to one of the Aggregators. The
Aggregators then interact with one another over `ROUND` rounds, where in
each round, each Aggregator produces a single outbound message. The outbound
messages are broadcast to all of the aggregators at the beginning of each round.
Eventually, each aggregator recovers a share of the output.

Input evaluation involves the following algorithms:

* `eval_setup() -> (public_param, verify_params: Vec[Bytes])` is the randomized
  setup algorithm used to generate the public parameter used by the Clients
  (`public_param`) and the verification parameters used by the Aggregators
  (`verify_params`, note that `len(input_shares) == SHARES`). The parameters are
  generated once and reused across multiple VDAF evaluations. The verification
  parameters are secret and MUST NOT be revealed to the Clients, Collector or
  other Aggregators.

  > TODO Decide how to express arrays of fixed length with Python hints and
  > replace `Vec[Bytes]` with a suitable expression.

* `eval_input(public_param, input) -> input_shares: Vec[Bytes]` is the
  randomized input-distribution algorithm run by each Client. It consumes the
  public parameter and input measurement and produces a sequence of input
  shares, one for each Aggregator (i.e., `len(input_shares) == SHARES`).

* `eval_init(verify_param, agg_param, nonce, input_share) -> (eval_state:
  EvalState)` is the deterministic evaluation-state initialization algorithm run
  by each Aggregator to begin evaluation. Its inputs are the aggregator's
  verification parameter (`verify_param`), the aggregation parameter
  (`agg_param`), the nonce provided by the environment (`nonce`, see
  {{run-vdaf}}), and one of the input shares generated by the client
  (`input_share`). Its outputs is the Aggregator's initial evaluation state.

* `EvalState.next(inbound: Vec[Bytes]) -> outbound` is the deterministic
  evaluation-state update algorithm run by each Aggregator. It updates the
  Aggregator's evaluation state (an instance of `EvalState`) and returns either
  its outbound message for the current round or, if this is the last round, its
  output share. An exception is raised if a valid output share could not be
  recovered. The input of this algorithm is the sequence of inbound messages
  from the previous round (i.e., `len(inbound) == SHARES`) or, if this is the
  first round, an empty vector.

The evaluation-state update accomplishes two tasks that are essential to most
schemes: recovery of output shares from the input shares, and a multi-party
computation carried out by the Aggregators to ensure that their output shares
are valid. The VDAF abstraction boundary is drawn so that an Aggregator only
recovers an output shares if the output share is deemed valid (at least, based
on the Aggregator's view of the protocol). Another way to draw this boundary
woulds be to have the Aggregators recover output shares first, then verify that
they are valid. The problem is that this allows the possibility of misusing the
API by, say, aggregating an invalid output share. Moreover, in some protocols, like
Prio+ [AGJOP21] it is necessary for the Aggregators to interact in order to
recover output shares at all.

Note that it is possible for a VDAF to specify `ROUNDS == 0`, in which case
each Aggregator runs the evaluation-state update algorithm once and immediately
recovers its output share without interacting with the other Aggregators.
However, most, if not all, constructions will require some amount of interaction
in order to ensure validity of the output shares (while also maintaining
privacy).

## Output Aggregation

~~~~
    Aggregator 0    Aggregator 1        Aggregator SHARES-1
      |               |                   |
      V               V                   V
    +-----------+   +-----------+       +-----------+
    | agg_init  |   | agg_init  |   ... | agg_init  |
    +-----------+   +-----------+       +-----------+
      |               |                   |
      V               |                   |
    +-----------+     |                   |
--->| agg_next  |     |                   |
    +-----------+     V                   |
      |             +-----------+         |
------------------->| agg_next  |         |
      |             +-----------+         V
      |               |                 +-----------+
--------------------------------------->| agg_next  |
      |               |                 +-----------+
      |               |                   |
      V               V                   V
     ...             ...                 ...
      |               |                   |
      V               |                   |
    +-----------+     |                   |
--->| agg_next  |     |                   |
    +-----------+     v                   |
      |             +-----------+         |
------------------->| agg_next  |         |
      |             +-----------+         v
      |               |                 +-----------+
--------------------------------------->| agg_next  |
      |               |                 +-----------+
      |               |                   |
      V               V                   V
    +-----------------------------------------------+
    | agg_output                                    |
    +-----------------------------------------------+
      |
      V
    Collector
~~~~
{: #agg-flow title="Aggregation of output shares. Each set of wires
entering from the left represent output shares recovered by the aggregators
by evaluating the VDAF on a set of input shares."}

Output aggregation involves the Aggregators and the Collector. This process,
illustrated in {{agg-flow}} runs concurrently with the input evaluation process.
Once an aggregator has recovered a valid output share, it adds it into its
long-running aggregation state locally; and once all of the inputs have been
processed, each Aggregator sends its aggregate share to the Collector, who
combines them to recover the final aggregate. This process involves the
following algorithms:

* `agg_init() -> AggState` is the deterministic aggregation-state initialization
  algorithm. It is run by each Aggregator before processing any Client input.

* `AggState.next(output_share)` is the deterministic aggregation-state update
  algorithm. It is run by an Aggregator immediately after it recovers a valid
  output share `output_share`.

* `agg_output(agg_states: Vec[AggStates]) -> agg` is the deterministic combines
  the aggregation state of each aggregator (note that `len(states) == SHARES`)
  into the final aggregate `agg`.

> TODO Maybe `AggState.next` (and maybe `agg_output`, too) should be randomized
> in order to allow the Aggregators (or the Collector) to add noise for
> differential privacy. (See the security considerations of [PPM].) Or is this
> out-of-scope of this document?

## Execution of a VDAF {#execution}

Executing a VDAF involves the concurrent evaluation of the VDAF on individual
inputs and aggregation of the recovered output shares. This is captured by the
following algorithm:

~~~
def run_vdaf(agg_param, nonces: Vec[Bytes], inputs: Vec[Bytes]):
  # Distribute long-lived evaluation parameters.
  (public_param, verify_params) = eval_setup()

  # Each aggregator initializes its aggregation state.
  agg_states = [ agg_init() for j in range(SHARES) ]

  for (nonce, input) in zip(nonces, inputs):
    # Each client shards its input into shares.
    input_shares = eval_input(public_param, input)

    # Each aggregator initializes its evaluation state.
    eval_states = []
    for j in range(SHARES):
      eval_states.append(eval_init(
          verify_params[j], agg_param, nonce, input_shares[j]))

    # Aggregators recover their output shares.
    inbound = []
    for i in range(ROUNDS+1):
      outbound = []
      for j in range(SHARES):
        outbound.append(eval_states[j].next(inbound))
      inbound = outbound

    # Each aggregator updates its aggregation state.
    for j in range(SHARES):
      agg_states[j].next(outbound[j])

  # Collector unshards the aggregate.
  return agg_output(agg_states)
~~~
{: #run-vdaf title="Execution of a VDAF."}

The inputs to this algorithm are the aggregation parameter `agg_param`, a list
of nonces `nonces`, and a list of Client inputs `inputs`. The aggregation
parameter is chosen by the aggregators prior to executing the VDAF. This
document does not specify how the nonces are chosen, but some of our security
considerations require that the nonces be unique for each VDAF evaluation. See
{{security}} for details.

Another important question this document leaves out of scope is how a VDAF is to
be executed by aggregators distributed over a real network. Algorithm `run_vdaf`
prescribes the protocol's execution in a "benign" environment in which there is
no adversary and messages are passed among the protocol participants over secure
point-to-point channels. In reality, these channels need to be instantiated by
some "wrapper protocol" that implements suitable cryptographic functionalities.
Moreover, some fraction of the aggregators (or clients) may be malicious and
diverge from their prescribed behaviors. {{security}} describes the execution of
the VDAF in various adversarial environments and what properties the wrapper
protocol needs to provide in each.

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

The etymology of the term `prio3` is that it descends from the original Prio
construction [CGB17], which was deployed in Firefox's origin telemetry project
(i.e., "prio1"). It generalizes the more recent deployment in the ENPA system
(i.e., "prio2") and is based on techniques described in [BBCGGI19].

## Dependencies

This section describes the cryptographic dependencies of `prio3`.

### Probabilistically Checkable Proofs {#pcp}

A Probabilistically Checkable Proof (PCP) is comprised of the following
algorithms:

* `pcp_prove(input: Vec[Field], prove_rand: Vec[Field], joint_rand: Vec[Field])
  -> proof: Vec[Field]` is the deterministic proof-generation algorithm run by
  the prover. Its inputs are the encoded input, the prover randomness
  `prove_rand`, and the joint randomness `joint_rand`. The former is used only
  by the prover and the latter is used by both the prover and verifier.

* `pcp_query(input: Vec[Field], proof: Vec[Field], query_rand: Vec[Field],
  joint_rand: Vec[Field]) -> verifier: Vec[Field]` is the query-generation
  algorithm run by the verifier. This is is used to "query" the input and proof.
  The result of the query is called the verifier message. In addition to the
  input and proof, this algorithm takes as input the query randomness
  `query_rand` and the joint randomness `joint_rand`. The former is used only by
  the verifier and the latter is the same randomness used by the prover.

* `pcp_decide(verifier: Vec[Field]) -> decision: Boolean` is the deterministic
  decision algorithm run by the verifier. It takes as input the verifier message
  and outputs a boolean indicating if the input from which it was generated is
  valid.

Our application requires that the PCP is "fully linear" in the sense defined in
[BBCGGI19]. As a practical matter, what this property implies is that the
query-generation algorithm can be run by each aggregator locally on its share of
the input and proof. The outputs can then be combined into the input to the
decision algorithm to decide if the input is valid.

Note that [BBCGGI19] defines a much larger class of proof systems; what is
called a PCP here is called a 1.5-round, public-coin, interactive oracle proof
system in the paper.

PCPs define the following constants:

* `JOINT_RAND_LEN` is the length of the joint randomness in number of field
  elements.
* `PROVE_RAND_LEN` is the length of the prover randomness.
* `QUERY_RAND_LEN` is the length of the query randomness.
* `INPUT_LEN` is the length of the input.
* `PROOF_LEN` is the length of the proof.
* `VERIFIER_LEN` is the length of the verifier message.

PCPs also have an associated type that defines the underlying finite field:

* `Field` is an element of a finite field. Associated functions:

  * `vec_zeros(len: Unsigned) -> output: Vec[Field]` returns a length-`len`
    vector of zeros.
  * `encode_vec(data: Vec[Field]) -> encoded_data: Bytes` represents the input
    `data` as a byte string `encoded_data`.
  * `decode_vec(encoded_data: Bytes) -> data: Vec[Field]` reverse `encoded_vec`,
    returning the vector of field elements encoded by `encoded_data`. Raises an
    exception if the input does not encode a valid vector of field elements.

  Associated constants:

  * `ENCODED_SIZE` is the size of each field element in bytes. [XXX Is this
    needed?]

Execution of a PCP is as follows:

~~~
def run_pcp(input, joint_rand, prove_rand, query_rand: Vec[Field]):
  assert(len(joint_rand, JOINT_RAND_LEN))
  assert(len(prove_rand, PROVE_RAND_LEN))
  assert(len(query_rand, QUERY_RAND_LEN))

  # Prover generates the proof.
  proof = pcp_prove(input, prove_rand, joint_rand)

  # Verifier queries the input and proof.
  verifier = pcp_query(input, proof, query_rand, joint_rand)

  # Verifier decides if the input is valid.
  return pcp_decide(verifier)
~~~
{: #run-pcp title="Execution of a fully linear PCP."}

### Key Derivation

A key-derivation scheme consists of the following algorithms:

* `get_key(init_key, input) -> key` derives a fresh key `key` from an initial
  `key` require `len(init_key) == KEY_SIZE` and auxiliary input `input`. It is
  required that `len(key) == KEY_SIZE` and `len(init_key) == KEY_SIZE`

* `get_key_stream(key) -> state: KeyStream` returns a key stream generator that
  is used to generate an arbitrary length stream of pseudorandom bytes. It is
  required that `len(key) == KEY_SIZE`.

* `key_stream_next(state: KeyStream, len: Unsigned) -> (new_state: KeyStream,
  output)` returns the next `len` bytes of the key stream and updates the key
  stream state. It is required that that `len(output) == len`.

[NOTE This closely resembles what people usually think of as an
extract-then-expand KDF, but differs somewhat in its syntax and, also, its
required security properties. Can we get the same functionality from something
that's more commonplace? HKDF doesn't fit the bill, unfortunately, because keys
can only be expanded to a fairly short length. Our application requires a rather
long key stream.]

Associated types:

* `KeyStream` represents the state of the key stream generator.

Associated constants:

* `KEY_SIZE` is the size of keys for the key-derivation scheme.

### Aggregable Encoding

The VDAF requires a method for encoding raw measurements as vectors of field
elements and decoding input shares into aggregable output shares. (Note that
this corresponds roughly to the notion of Affine-aggregatable encodings (AFEs)
from [CGB17].)

* `encode_input(measurement: Bytes) -> input: Vec[Field]` encodes a raw
  measurement as a vector of field elements. The type `Field` MUST be the same
  as the field type associated with the PCP (see {{pcp}}). An error raised if
  the measurement cannot be represented as an input.

* `decode_output(input: Vec[Field]) -> output: Vec[Field]` maps an encoded input
  to an aggregable output. It is required that `len(output) <= len(input)`.

## Helper Functions

TODO

* `expand(seed, length: U32) -> output: Vec[Field]`
* `encode_state`
* `encode_helper_share`
* `encode_leader_share`
* `decode_share` raises `ERR_DECODE`
* `encode_verifier_share`
* `decode_verifier_share` raises `ERR_DECODE`

## Construction

~~~
def eval_setup():
  k_query_init = gen_rand(KEY_SIZE)
  verify_param = [ (j, k_query_init) for j in range(SHARES) ]
  return (None, verify_param)
~~~
{: #prio3-eval-setup title="The setup algorithm for prio3."}

~~~
def eval_input(_, measurement):
  input = encode_input(measurement)
  k_joint_rand = zeros(SEED_SIZE)

  # Generate input shares.
  leader_input_share = input
  k_helper_input_shares = []
  k_helper_blinds = []
  k_helper_hints = []
  for j in range(SHARES-1):
    k_blind = gen_rand(KEY_SIZE)
    k_share = gen_rand(KEY_SIZE)
    helper_input_share = expand(k_share, INPUT_LEN)
    leader_input_share -= helper_input_share
    k_hint = get_key(k_blind,
        byte(j+1) + encode_vec(helper_input_share))
    k_joint_rand ^= k_hint
    k_helper_input_shares.append(k_share)
    k_helper_blinds.append(k_blind)
    k_helper_hints.append(k_hint)
  k_leader_blind = gen_rand(KEY_SIZE)
  k_leader_hint = get_key(k_leader_blind,
      byte(0) + encode_vec(leader_input_share))
  k_joint_rand ^= k_leader_hint

  # Finish joint randomness hints.
  for j in range(SHARES-1):
    k_helper_hints[i] ^= k_joint_rand
  k_leader_hint ^= k_joint_rand

  # Generate the proof shares.
  joint_rand = expand(k_joint_rand, JOINT_RAND_LEN)
  prove_rand = expand(gen_rand(KEY_SIZE), PROVE_RAND_LEN)
  leader_proof_share = pcp_prove(input, prove_rand, joint_rand)
  k_helper_proof_shares = []
  for j in range(SHARES-1):
    k_share = gen_rand(KEY_SIZE)
    k_helper_proof_shares.append(k_share)
    helper_proof_share = expand(k_share, PROOF_LEN)
    leader_proof_share -= helper_proof_share

  output = []
  output.append(encode_leader_share(
    leader_input_share,
    leader_proof_share,
    k_leader_blind,
    k_leader_hint,
  ))
  for j in range(SHARES-1):
    output.append(encode_helper_share(
      k_helper_input_share[j],
      k_helper_proof_share[j],
      k_helper_blinds[j],
      k_helper_hints[j],
    ))
  return output
~~~
{: #prio3-eval-input title="Input-distribution algorithm for prio3."}

~~~
def eval_start(verify_param, _, nonce, r_input_share):
  (j, k_query_init) = verify_param
  (input_share, proof_share,
   k_blind, k_hint) = decode_share(input_share)
  if j > 0: # helper
    input_share = expand(input_share)
    proof_share = expand(proof_share)

  k_joint_rand_share = get_key(k_blind, byte(j) + input_share)
  k_joint_rand = k_hint ^ k_joint_rand_share
  k_query_rand = get_key(k_query_init, byte(255) + nonce)

  joint_rand = expand(k_joint_rand, JOINT_RAND_LEN)
  query_rand = expand(k_query_rand, QUERY_RAND_LEN)
  verifier_share = pcp_query(
      input_share, proof_share, query_rand, joint_rand)

  state = encode_state(k_joint_rand, decode_output(input_share))
  output = encode_verifier_share(k_joint_rand, verifier_share)
  return (state, output)
~~~
{: #prio3-eval-start title="Verify-start algorithm for prio3."}

`ROUNDS` is 1 for Prio3, and so no `eval_next` definition is provided.

~~~
def eval_finish(state: State, r_verifier_shares):
  if len(r_verifier_shares) != s: raise ERR_DECODE

  k_joint_rand = zeros(KEY_SIZE)
  verifier = vec_zeros(VERIFIER_LEN)
  for r_share in r_verifier_shares:
    (k_joint_rand_share,
     verifier_share) = decode_verifier_share(r_share)

    k_joint_rand ^= k_joint_rand_share
    verifer += verifier_share

  if k_joint_rand != state.k_joint_rand: raise ERR_INVALID
  if not pcp_decide(verifier): raise ERR_INVALID
  return state.input_share
~~~
{: #prio3-eval-finish title="Verify-finish algorithm for prio3."}

Auxiliary functions:

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
