---
title: "Verifiable Distributed Aggregation Functions"
abbrev: "VDAF"
docname: draft-patton-cfrg-vdaf-latest
category: info

ipr: trust200902
area: IRTF
workgroup: CFRG
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
 -
    name: Christopher Patton
    organization: Cloudflare, Inc.
    email: cpatton@cloudflare.com
 -
    name: Richard L. Barnes
    organization: Cisco
    email: rlb@ipv.sx

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

  OriginTelemetry:
    title: "Origin Telemetry"
    date: 2020
    target: https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/collection/origin.html

  ENPA:
    title: "Exposure Notification Privacy-preserving Analytics (ENPA) White Paper"
    date: 2021
    target: https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ENPA_White_Paper.pdf

  PPM:
    title: "Privacy Preserving Measurement"
    date: 2021
    author:
      - ins: T. Geoghagen
      - ins: C. Patton
      - ins: E. Rescorla
      - ins: C. Wood

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
systems at scale. There is substantial overlap, however, between information
that is valuable to measure and information that users consider private.

For example, consider an application that provides health information to users.
The operator of an application might want to know which parts of their
application are used most often, as a way to guide future development of the
application.  Specific users' patterns of usage, though, could reveal sensitive
things about them, such as which users are researching a given health condition.

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

VDAF schemes achieve their privacy goal by distributing the computation of the
aggregate among a number of non-colluding aggregation servers. As long as a
subset of the servers executes the protocol honestly, VDAFs guarantee that no
input is ever visible in the clear. At the same time, VDAFs are "verifiable" in
the sense that malformed inputs that would otherwise garble the output of the
computation can be detected and removed from the set of inputs.

The cost of achieving these security properties is the need for multiple servers
to participate in the protocol, and the need to ensure they do not collude to
undermine the VDAF's privacy guarantees. However, recent implementation
experience has shown that deployment of these schemes is practical.  The Prio
system (essentially a VDAF) has been deployed in systems supporting hundreds of
millions of users: The Mozilla Origin Telemetry project [OriginTelemetry] and
the Exposure Notification Private Analytics collaboration among the Internet
Security Research Group, Google, Apple, and others [ENPA].

The VDAF abstraction laid out in {{vdaf}} represents a class of multi-party
protocols for privacy-preserving measurement proposed in the literature. These
protocols vary in their operational and security considerations, sometimes in
subtle, but consequential, ways. This document therefore has two important
goals:

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

* `byte(int: Unsigned) -> Byte` returns the representation of `int` as a byte.
  Raises an error if `int > 255`.

# Overview {#overview}

In a private measurement system, we distinguish three types of actors: Clients,
Aggregators, and Collectors.  The overall flow of the measurement process is as
follows:

* Clients are configured with public parameters for a set of Aggregators.
* To submit an individual measurement, a Client shards the measurement into
  "input shares" and sends one input share to each Aggregator.
* The aggregators verify the validity of the input shares, producing a set of
  output shares.
    * Output shares are in one-to-one correspondence with the input shares.
    * Just as each Aggregator receives one input share of each input, at the end
      of the validation process, each aggregator holds one output share.
    * In most VDAFs, aggregators will need to exchange information among
      themselves as part of the validation process.
* Each aggregator combine the output shares across inputs in the batch to
  compute shares of the desired aggregate.
* The aggregators submit their aggregate shares to the collector, who combines
  them to obtain the aggregate result over the batch.

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

      Input shares           Aggregate shares
~~~
{: #overall-flow title="Overall data flow of a VDAF"}

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
Aggregators to augment a basic client-server protocol.

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

## Input Evaluation

> TODO separate lists for (1) setup (2) client and (3) aggregator.

~~~~
    Client
      |
      V
    +----------------------------------------------+
    | eval_input                                   |
    +----------------------------------------------+
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

> Split function lists into Aggregator operations and Collector operations.

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

* `agg_output(agg_states: Vec[AggStates]) -> agg` is run by the Collector in
  order to compute the final aggregate from the Aggregators' aggregation states.
  (Note that `len(states) == SHARES`.) This algorithm is deterministic.

> OPEN ISSUE Maybe `AggState.next` (and maybe `agg_output`, too) should be
> randomized in order to allow the Aggregators (or the Collector) to add noise
> for differential privacy. (See the security considerations of [PPM].) Or is
> this out-of-scope of this document?

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

> NOTE This construction has not undergone significant security analysis.

> NOTE An implementation of this VDAF can be found
> [here](https://github.com/abetterinternet/libprio-rs/blob/main/src/vdaf/prio3.rs).

This section describes a VDAF suitable for the following data aggregation task.
Each Client measurement is encoded as a vector over a finite field, and the
aggregate is computed by summing the vectors element-wise. Validity is defined
via an arithmetic circuit `C` that takes as input a vector of field elements `x`
and outputs `0` if the input is valid. Otherwise, if `C(x) != 0`, then the input
is deemed invalid. A number of useful measurement types can be defined this way:

* Simples statistics, like sum, average, and standard deviation.
* Estimation of quantiles, via a histogram.
* Linear regression.
* Frequency estimates for arbitrary inputs, via count-min sketch or counting
  Bloom filter.

This VDAF does not have an aggregation parameter, hence the input shares are
identical to the output shares. See {{hits}} for an example of a VDAF that makes
meaningful use of the aggregation parameter.

The construction is derived from the original Prio system [CGB17], which is
defined for the same class of aggregation tasks. However, `prio3` takes
advantage of optimizations described later in [BBCGGI19] that improve
communication complexity significantly. The etymology of the term `prio3` is
that it descends from the original Prio construction. A second iteration was
deployed in the [ENPA] system, and like the VDAF described here, the ENPA system
was built from techniques introduced by [BBCGGI19]. However, was specialized for
a particular measurement type. The goal of `prio3` is to provide the same level
of generality as `prio1`.

## Overview {#prio3-overview}

The way `prio3` ensures privacy is quite simple: the Client shards its encoded
input vector `x` into a number of additive secret shares, one for each
Aggregator. Aggregators sum up their vector shares locally, and once enough
shares have been aggregated, each sends its share of the aggregate vector to the
Collector, who recovers the aggregate by adding up the vectors. The main problem
we have is ensuring that the input shares generated by the Client add up to a
valid input, i.e., that `C(x)=0`.

The solution introduced by [BBCGGI19] is what they call a zero-knowledge proof
system on distributed data. Viewing the Client as the prover and the Aggregators
as the (distributed) verifier, the goal is to devise a protocol by which the
Client convinces the Aggregators that they hold secret shares of a valid input,
without revealing the input itself. The core tool for accomplishing this task is
a refinement of Probabilistically Checkable Proof (PCP) systems called a Fully
Linear Proof (FLP) system.

We describe FLPs in detail below. Briefly, the Client generates a "proof" that
`C(x)=0` holds and distributes additive shares of the proof among the
Aggregators. Each Aggregator then performs a computation on its input share and
proof share locally and sends the result of that computation to the other
aggregators. Combining the results yields the result of evaluation the circuit
`C` on input `x`, without leaking the value of `x` itself.

`prio3` can be viewed as a transformation of a particular class of FLP systems
into a VDAF. In {{prio3-deps}} we describe the building blocks used in this
transform, including the syntax for FLPs. The construction is given in
{{prio3-construction}}.

## Dependencies {#prio3-deps}

### Fully Linear Proof (FLP) Systems {#flp}

Conceptually, an FLP system is a two-party protocol executed by a prover and a
verifier. In actual use, however, the prover's computation is carried out by the
Client, and the verifier's computation is distributed among the Aggregators.
(More on this in {{prio3-construction}}. An FLP specifies the following
algorithms:

* `flp_prove(input: Vec[Field], prove_rand: Vec[Field], joint_rand: Vec[Field])
  -> proof: Vec[Field]` is the deterministic proof-generation algorithm run by
  the prover. Its inputs are the encoded input, the "prover randomness"
  `prove_rand`, and the "joint randomness" `joint_rand`. The proof randomness is
  used only by the prover; the joint randomness is shared by both the prover and
  verifier.

* `flp_query(input: Vec[Field], proof: Vec[Field], query_rand: Vec[Field],
  joint_rand: Vec[Field]) -> verifier: Vec[Field]` is the query-generation
  algorithm run by the verifier. This is is used to "query" the input and proof.
  The result of the query (i.e., the output of this function) is called the
  "verifier message". In addition to the input and proof, this algorithm takes
  as input the query randomness `query_rand` and the joint randomness
  `joint_rand`.  The former is used only by the verifier and the latter is the
  same randomness used by the prover.

* `flp_decide(verifier: Vec[Field]) -> decision: Boolean` is the deterministic
  decision algorithm run by the verifier. It takes as input the verifier message
  and outputs a boolean indicating if the input from whence it was generated is
  valid.

A concrete FLP defines the following constants:

* `JOINT_RAND_LEN: Unsigned` is the length of the joint randomness in number of
  field elements.
* `PROVE_RAND_LEN: Unsigned` is the length of the prover randomness.
* `QUERY_RAND_LEN: Unsigned` is the length of the query randomness.
* `INPUT_LEN: Unsigned` is the length of the input.
* `OUTPUT_LEN: Unsigned` is the length of the aggregable output. (See
  {{prio3-aggregable}}.)
* `PROOF_LEN: Unsigned` is the length of the proof.
* `VERIFIER_LEN: Unsigned` is the length of the verifier message.

PLP systems also have an associated type that defines a finite field field
`GF(p)` for prime `p`:

* `Field` is an element of a finite field. Associated functions:

  * `vec_zeros(len: Unsigned) -> output: Vec[Field]` returns a length-`len`
    vector of zeros.
  * `encode_vec(data: Vec[Field]) -> encoded_data: Bytes` represents the input
    `data` as a byte string `encoded_data`.
  * `decode_vec(encoded_data: Bytes) -> data: Vec[Field]` reverse `encoded_vec`,
    returning the vector of field elements encoded by `encoded_data`. Raises an
    exception if the input does not encode a valid vector of field elements.

  Associated constants of `Field`:

  * `ENCODED_SIZE: Unsigned` is the size of each field element in bytes.
  * `MODULUS: Unsigned` equal to `p`, the field's prime modulus.

Our application requires that the FLP is "fully linear" in the sense defined in
[BBCGGI19]. As a practical matter, what this property implies is that the
query-generation algorithm can be run by each aggregator locally on its share of
the input and proof, and the results can be combined to recover the verifier
message. In the remainder, the result generated by an aggregator will be
referred to as its "verifier share".

Note that [BBCGGI19] defines a much larger class of fully linear proof systems;
what is called a FLP here is called a 1.5-round, public-coin, interactive oracle
proof system in their paper.

An FLP is executed by the prover and verifier as follows:

~~~
def run_flp(input, joint_rand, prove_rand, query_rand: Vec[Field]):
  assert(len(joint_rand, JOINT_RAND_LEN))
  assert(len(prove_rand, PROVE_RAND_LEN))
  assert(len(query_rand, QUERY_RAND_LEN))

  # Prover generates the proof.
  proof = flp_prove(input, prove_rand, joint_rand)

  # Verifier queries the input and proof.
  verifier = flp_query(input, proof, query_rand, joint_rand)

  # Verifier decides if the input is valid.
  return flp_decide(verifier)
~~~
{: #run-flp title="Execution of an FLP."}

The proof system is constructed so that, if `input` is a valid input, then
`run_flp(input, joint_rand, prove_rand, query_rand)` always returns `True`. On
the other hand, if `input` is invalid, then as long as `joint_rand` and
`query_rand` are generated uniform randomly, the output is `False` with
overwhelming probability. In addition, the proof system is designed so that the
verifier message leaks nothing about the input (in an information theoretic
sense). See Definition 3.9 from [BBCGGI19] for details.

### Key Derivation

In addition to the core FLP system functionality, the `prio3` VDAF requires a
way to derive symmetric keys and to expand keys into an arbitrary length key
stream. A key-derivation scheme consists of the following algorithms:

* `get_key(init_key, aux_input) -> key` derives a fresh key `key` from an
  initial `init_key` and auxiliary input `aux_input`. It is required that
  `len(init_key) == KEY_SIZE` `len(key) == KEY_SIZE`.

* `get_key_stream(key) -> state: KeyStream` returns a key stream generator that
  is used to generate an arbitrary length stream of pseudorandom bytes. It is
  required that `len(key) == KEY_SIZE`.

* `KeyStream.next(len: Unsigned) -> (new_state: KeyStream, output)` returns the
  next `len` bytes of the key stream and updates the key stream generator state.
  It is required that that `len(output) == len`.

> TODO This functionality closely resembles what people usually think of as an
> extract-then-expand KDF, but differs somewhat in its syntax and, also, its
> required security properties. Can we get the same functionality from something
> that's more commonplace? HKDF doesn't fit the bill, unfortunately, because
> keys can only be expanded to a fairly short length. Our application requires a
> rather long key stream.

Associated types:

* `KeyStream` represents the state of the key stream generator.

Associated constants:

* `KEY_SIZE` is the size of keys for the key-derivation scheme.

### Aggregable Encoding {#prio3-aggregable}

Finally, The VDAF requires a method for encoding raw measurements as vectors of
field elements and decoding input shares into aggregable output shares. (Note
that this corresponds roughly to the notion of Affine-aggregatable encodings
(AFEs) from [CGB17].) This involves two algorithms:

* `encode_input(measurement: Bytes) -> input: Vec[Field]` encodes a raw
  measurement as a vector of field elements. The type `Field` MUST be the same
  as the field type associated with the FLP (see {{flp}}). Additionally, the
  returned `input` MUST be valid as defined by the FLP. An error is raised if
  the measurement cannot be represented as a valid input.

* `decode_output(input: Vec[Field]) -> output: Vec[Field]` maps an encoded input
  to an aggregable output. The length of the output MUST be `OUTPUT_LEN` as
  specified by the FLP.

Note that the decoding step is useful because, for some FLPs, the encoded input
includes redundant field elements that are useful for checking the proof, but
which are not needed after the proof has been checked.

## Construction {#prio3-construction}

This VDAF involves a single round of communication (`ROUND == 1`). It is defined
for at least two aggregators, but at most 255 (`2 <= SHARES <= 255`).

### Input Evaluation

#### Setup

The setup algorithm generates a symmetric key shared by all of the aggregators.
The key is used to derive unique joint randomness for the FLP query-generation
algorithm run by the aggregators during input evaluation.

~~~
def eval_setup():
  k_query_init = gen_rand(KEY_SIZE)
  verify_param = [ (j, k_query_init) for j in range(SHARES) ]
  return (None, verify_param)
~~~
{: #prio3-eval-setup title="The setup algorithm for prio3."}

#### Client

Recall that the syntax for FLP systems calls for "joint randomness" shared by
the prover (i.e., the Client) and the verifier (i.e., the Aggregators). VDAFs
have no such notion, of course. Instead, the Client will derive the joint
randomness from its input in a way that allows the Aggregators to reconstruct
the joint randomness from their input shares. (Note that this idea is adapted
from Section 6.2.3 of [BBCGGI19].)

The input-distribution algorithm involves the following steps:

1. Encode the Client's raw measurement as an input for the FLP
1. Shard the input into a sequence of input shares.
1. Derive the joint randomness from the input shares.
1. Run the FLP proof-generation algorithm using prover randomness generated
   locally.
1. Shard the proof into a sequence of input shares.

The input and proof shares of one Aggregator -- below we call it the "leader" --
are vectors of field elements. For shares of the other aggregators -- below we
call them the "helpers" -- as constant-sized symmetric keys. This is
accomplished by mapping the key to a key stream and expanding the key stream
into a pseudorandom vector of field elements. In addition to the key-derivation
scheme described in {{prio3-deps}}, this requires a helper function, called
`expand`, defined in {{prio3-helper-functions}}.

This algorithm also makes use of a pair of helper functions for encoding the
leader share and helper share. These are called `encode_leader_share` and
`encode_helper_share` respectively.

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
  leader_proof_share = flp_prove(input, prove_rand, joint_rand)
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

#### Aggregator

The high level idea is that each of the Aggregators runs the FLP
query-generation algorithm on its share of the input and proof and exchange
shares of the verifier message. Once they've done that, each runs the FLP
decision algorithm on the verifier message locally to decide whether to accept.

In addition, the Aggregators must ensure that they have all used the same joint
randomness for the query-generation algorithm. The joint randomness is
generated by a symmetric key. Each Aggregator derives an XOR secret share of
this key from its input share and "blind" generated by the client. Before it can
run the query-generation algorithm, it must first gather the XOR secret shares
derived by the other Aggregators.

So that the Aggregators can avoid an extra round of communication, the client
sends each Aggregator a "hint" equal to the XOR of the other Aggregators' shares
of the joint randomness key. However, this leaves open the possibility that the
client cheated by, say, forcing the Aggregators to use joint randomness biases
the proof check procedure in someway in its favor. To mitigate this, the
Aggregators also check that they have all computed the same joint randomness key
before accepting their output shares.

> NOTE This optimization somewhat diverges from Section 6.2.3 of [BBCGGI19].
> We'll need to understand better how this impacts security.

The evaluation state is initialized as follows. The `decode_share` algorithm
used to decode the leader (or helper) share is defined in
{{prio3-helper-functions}}.

~~~
def eval_init(verify_param, _, nonce, r_input_share):
  (j, k_query_init) = verify_param

  if j == 0: # leader
    (input_share, proof_share,
     k_blind, k_hint) = decode_leader_share(r_input_share)
  else:
    (k_input_share, k_proof_share,
     k_blind, k_hint) = decode_helper_share(r_input_share)
    input_share = expand(input_share, INPUT_LEN)
    proof_share = expand(proof_share, PROOF_LEN)

  k_joint_rand_share = get_key(k_blind, byte(j) + input_share)
  k_joint_rand = k_hint ^ k_joint_rand_share
  k_query_rand = get_key(k_query_init, byte(255) + nonce)

  joint_rand = expand(k_joint_rand, JOINT_RAND_LEN)
  query_rand = expand(k_query_rand, QUERY_RAND_LEN)
  verifier_share = flp_query(
      input_share, proof_share, query_rand, joint_rand)

  return EvalState(
    k_joint_rand,
    k_joint_rand_share,
    verifier_share,
    decode_output(input_share),
  )
~~~
{: #prio3-eval-init title="Evaluation-state initialization algorithm for prio3."}

The `EvalState` type is defined as follows. It involves two helper functions,
`encode_verifer_share` and `decode_verifier_share`, both of which are defined in
{{prio3-helper-functions}}.

~~~
class EvalState:
  def __init__(k_joint_rand,
               k_joint_rand_share,
               verifier_share: Vec[Field],
               output_share: Vec[Field]):
    self.k_joint_rand = k_joint_rand
    self.k_joint_rand_sahre = k_joint_rand_share
    self.verifier_share = verifier_share
    self.output_share = output_share
    self.state = "ready"

  def next(self, inbound: Vec[Bytes]):
    if self.state == "ready" and len(inbound) == 0:
      self.state = "waiting"
      return encode_verifier_share(
        self.k_joint_rand_share,
        self.verifier_share,
      )

    elif self.state == "waiting" and len(inbound) == SHARES:
      k_joint_rand = zeros(KEY_SIZE)
      verifier = vec_zeros(VERIFIER_LEN)
      for r_share in r_verifier_shares:
        (k_joint_rand_share,
         verifier_share) = decode_verifier_share(r_share)

        k_joint_rand ^= k_joint_rand_share
        verifer += verifier_share

      if k_joint_rand != state.k_joint_rand: raise ERR_INVALID
      if not flp_decide(verifier): raise ERR_INVALID
      return state.output_share

    else: raise ERR_INVALID_STATE
~~~
{: #prio3-eval-state title="Evaluation state for prio3."}

> NOTE `JOINT_RAND_LEN` may be `0`, in which case the joint randomness
> computation is not necessary. Should we bake this option into the spec?

### Output Aggregation

#### Aggregator

~~~
def agg_init():
  return AggState()

class AggState:
  def __init__():
    self.share = vec_zeros(OUTPUT_LEN)

  def next(self, output_share: Vec[Field]):
    self.share += output_share
~~~
{: #prio3-agg-state title="Aggregation state for prio3."}

#### Collector

~~~
def agg_output(agg_states: Vec[AggState]):
  agg = vec_zeros(OUTPUT_LEN)
  for agg_state in agg_states:
    agg += agg_state.share
  return agg
~~~
{: #prio3-agg-output title="Computation of the aggregate for prio3."}

### Helper Functions {#prio3-helper-functions}

> TODO Specify the following functionalities.

* `expand(key, len: Unsigned) -> vec: Vec[Field]` maps a key of length
  `KEY_SIZE` to a length-`len` vector of field elements. This is constructed
  from the key-derivation scheme.
* `encode_leader_share(input_share: Vec[Field], proof_share: Vec[Field], blind,
  hint) -> encoded: Bytes` encodes a leader share as a byte string.
* `encode_helper_share(input_share, proof_sahre, blind, hint) -> encoded: Bytes`
  encodes a helper share as a byte string.
* `decode_leader_share` and `decode_helper_share` decode a leader and helper
  share respectively.
* `encode_verifier_share(hint, verifier_share: Vec[Field]) -> encoded` encodes a
  hint and verifier share as a byte string.
* `decode_verifier_share` decodes a verifier share.

# hits {#hits}

TODO

* Input is a bit string of a specific length.
* Input shares are IDPF shares and the correlated randomness for each level of
  the tree.
* Aggregation parameter is a set of candidate prefixes, all having the same
  length.
* Output shares are secret shares of a vector of field elements, each
  corresponding to a counter for one of the candidate prefixes.

## Dependencies

[TODO Clarify which of these can be assumed and which need to be explicitly
defined]

### Descriptions of finite fields

We assume a structure for describing IDPF output groups, named `ValueType`.
For verifiable heavy hitters, we need an IDPF that at each level has two field
elements as outputs, and so the value type would be pairs of field elements.
The IDPF key generation and evaluation functions will allow a different `ValueType`
parameter per bit in the IDPF domain, which allows us to use different types at
the output layer, required for extractability. See [BBCGGI21, Section 4.3] for
details. We assume a function `get_value_type(n: Unsigned) -> ValueType` that
returns the type for bit index `n`. We use `ValueType` to refer to a description
of a given group, and`Value` to refer to an actual element of the group.

### Incremental Distributed Point Functions (IDPFs)

An IDPF is defined over a domain of size `2**d`. The client can specify an
index `alpha` and values `beta`, one for each level `l` in `[d]`. The key
generation generates two IDPF keys that individually hide `alpha` and `beta`.
When locally evaluated at any point `x` in `2**l` at level `l`, the IDPF
returns shares of `beta[l]`, if `x` is the `l`-bit prefix of `alpha`, and
shares of zero otherwise. If elements of `beta` are tuples, the additive
sharing is done element-wise.

- `idpf_gen(alpha: Unsigned, beta: Vec[Value]) -> (idpf_key1: Bytes, `
`idpf_key2: Bytes)`:
Takes as input the index and values for the IDPF. Returns two serialized IDPF
keys, one for each helper server.
- `idpf_eval_next(state: State, dpf_key: Bytes, x: Unsigned) `
`-> (new_state: State, value: Value)`:
Evaluates the given key at index `x`, at the next prefix length that hasn't
been evaluated yet for `state`, returning a secret-shared value.

### Malicious sketching for IDPFs

~~~
def verify_sketch_round_1(idpf_output: Vec[Value], correlation_share, \
    verify_rand: Bytes, level: Unsigned):
  # Expand common randomness and compute verification message
  r = expand_rand(verify_rand, level, len(idpf_output))
  r_squared = [v*v for v in r]
  ver_msg_1 = inner_product(
    [value[0] for value in idpf_output,
    r
  )
  ver_msg_2 = inner_product(
    [value[0] for value in idpf_output,
    r_squared
  )
  ver_msg_3 = inner_product(
    [value[1] for value in idpf_output],
    r
  )
  outbound_message = {
    ver_msg_1: ver_msg_1 + correlation_share.a
    ver_msg_2: ver_msg_2 + correlation_share.b
    ver_msg_3: ver_msg_3 + correlation_share.c
  }
  state = {
    ver_msg_1: ver_msg_1,
    ver_msg_2: ver_msg_2,
    ver_msg_3: ver_msg_3,

  return (state, outbound_message)
~~~

~~~
def verify_sketch_round_2(state, inbound_message, correlation_share):
  ver_msg_1 = state.ver_msg_1 + inbound_message.ver_msg_1
  ver_msg_2 = state.ver_msg_2 + inbound_message.ver_msg_2
  ver_msg_3 = state.ver_msg_3 + inbound_message.ver_msg_3
  verification = ver_msg_1**2 - ver_msg_2 - ver_msg_3 + \
    correlation_share.A * ver_msg_1 + correlation_share.B
  if verification == 0:
    return True
  else:
    return False
~~~

## Construction

~~~
def vdaf_setup(n: Unsigned):
  public_param = {
    n: n
  }
  return (public_param, None)
~~~

~~~
def vdaf_input(public_param, input):
  assert(log2(input) < public_param.n)
  beta = []
  correlation_shares_0 = [], correlation_shares_1 = []
  for l in range(public_param.n):
    # Construct values of the form (1, k), where k is a random field element.
    _, field = get_value_type(l)
    k = get_random_element(field)
    beta += [(1, k)]
    # Create secret shares of correlations to aid the servers' computation
    a, b, c = get_random_element(field), get_random_element(field), \
      get_random_element(field)
    A = -2*a+k
    B = a*a + b - a * k + c
    correlation_shares_0 += [{
      a: get_random_element(field),
      b: get_random_element(field),
      c: get_random_element(field),
      A: get_random_element(field),
      B: get_random_element(field),
    }]
    correlation_shares_1 += [{
      a: a - correlation_shares_0[l]
      b: b - correlation_shares_0[l]
      c: c - correlation_shares_0[l]
      A: A - correlation_shares_0[l]
      B: B - correlation_shares_0[l]
    }]
  key_0, key_1 = idpf_gen(input, beta)
  return ((key_0, correlation_shares_0), (key_1, correlation_shares_1))
~~~

~~~
def vdaf_start(verify_param, public_param, nonce, input_share):
  key, correlation_share = input_share

  # Expand left and right children of the DPF tree.
  state_left, value_left = idpf_eval_next(None, key, 0)
  state_right, value_right = idpf_eval_next(None, key, 1)
  idpf_states = [state_left, state_right]
  idpf_output = [value_left, value_right]
  prefixes = [0, 1]

  verification_state, outbound_message = verify_sketch_round_1(idpf_output, \
    correlation_share[0], nonce, 0)

  state = {
    key: key,
    correlation_share: correlation_share,
    idpf_states: idpf_states,
    level: 0,
    prefixes: prefixes
    verification_round: 1
    verification_state: verification_state,
  }
  return (state, outbound_message)
~~~

~~~
def vdaf_next(state, inbound_messages):
  TODO.
~~~

# Security Considerations {#security}

> NOTE: This is a brief outline of the security considerations.  This section
> will be filled out more as the draft matures and security analyses are
> completed.

A VDAF is the core of a private measurement system, but needs to be realized
within an application.  The application will need to assure a few security
properties, for example:

* Securely provisioning clients with information about aggregators
* Configuring secure communications:
  * Confidential and authentic channels among aggregators, and
    between the aggregators and the collector
  * Confidential and aggregator-authenticated channels between clients and
    aggregators
* Enforcing the non-collusion properties required of the specific VDAF in use

In such an environment, a VDAF provides the high-level privacy property
described above: The collector learns only the aggregate measurement, and
nothing about individual measurements aside from what can be inferred from the
aggregate.  The aggregators learn neither individual measurements nor the
aggregate measurement.  The collector is assured that the aggregate statistic
accurately reflects the inputs as long as the aggregators correctly executed
their role in the VDAF.

The verification component of a VDAF bounds the degree to which malicious
clients can corrupt aggregate measurements by submitting malformed inputs.
Different VDAFs allow different checks to be done on the correctness of the
input.  These controls, however, are addressed at the level of individual
measurements, and do not prevent a malicious client from submitting multiple
valid inputs that would collectively result in an incorrect aggregate (a flavor
of Sybil attack [Dou02]).
Applications can guard against these risks by adding additional controls on
measurement submission, such as client authentication and rate limits.

VDAFs do not inherently provide differential privacy [Vad16].  The VDAF approach
to private measurement can be viewed as complementary to differential privacy,
relying on non-collusion instead of statistical noise to protect the privacy of
hte inputs.  It is possible that a future VDAF could incorporate differential
privacy features, e.g., by injecting noise at the input stage and removing it
during aggregation.


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

Thanks to Henry Corrigan-Gibbs and Christopher Wood for useful feedback on the
syntax of VDAF schemes.
