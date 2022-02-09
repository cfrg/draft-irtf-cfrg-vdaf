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
 -
    name: Phillipp Schoppmann
    organization: Google
    email: schoppmann@google.com

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
    date: 2021
    target: https://ia.cr/2021/576

  BBCGGI19:
    title: "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    date: 2019
    seriesinfo: CRYPTO 2019
    target: https://ia.cr/2019/188

  BBCGGI21:
    title: "Lightweight Techniques for Private Heavy Hitters"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    date: 2021
    seriesinfo: IEEE S&P 2021
    target: https://ia.cr/2021/017

  CGB17:
    title: "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"
    author:
      - ins: H. Corrigan-Gibbs
      - ins: D. Boneh
    date: 2017
    seriesinfo: NSDI 2017
    target: https://dl.acm.org/doi/10.5555/3154630.3154652

  Dou02:
    title: "The Sybil Attack"
    author:
      - ins: J. Douceur
    date: 2002
    seriesinfo: IPTPS 2002
    target: https://doi.org/10.1007/3-540-45748-8_24

  Dwo06:
    title: "Differential Privacy"
    author:
      - ins: C. Dwork
    date: 2006
    seriesinfo: ICALP 2006
    target: https://link.springer.com/chapter/10.1007/11787006_1

  EPK14:
    title: "RAPPOR: Randomized Aggregatable Privacy-Preserving Ordinal Response"
    author:
      - ins: Ú. Erlingsson
      - ins: V. Pihur
      - ins: A. Korolova
    date: 2014
    seriesinfo: CCS 2014
    target: https://dl.acm.org/doi/10.1145/2660267.2660348

  ENPA:
    title: "Exposure Notification Privacy-preserving Analytics (ENPA) White Paper"
    date: 2021
    target: https://covid19-static.cdn-apple.com/applications/covid19/current/static/contact-tracing/pdf/ENPA_White_Paper.pdf

  GI14:
    title: "Distributed Point Functions and Their Applications"
    author:
      - ins: N. Gilboa
      - ins: Y. Ishai
    date: 2014
    seriesinfo: EUROCRYPT 2014
    target: https://link.springer.com/chapter/10.1007/978-3-642-55220-5_35

  OriginTelemetry:
    title: "Origin Telemetry"
    date: 2020
    target: https://firefox-source-docs.mozilla.org/toolkit/components/telemetry/collection/origin.html

  Vad16:
    title: "The Complexity of Differential Privacy"
    author:
      - ins: S. Vadhan
    date: 2016
    target: https://link.springer.com/chapter/10.1007/978-3-319-57048-8_7

--- abstract

This document describes Verifiable Distributed Aggregation Functions (VDAFs), a
family of multi-party protocols for computing aggregate statistics over user
measurements. These protocols are designed to ensure that, as long as at least
one aggregation server executes the protocol honestly, individual measurements
are never seen by any server in the clear. At the same time, VDAFs allow the
servers to detect if a malicious or misconfigured client submitted an
input that would result in an incorrect aggregate result.

--- middle

# Introduction

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
measurement influences the value of the aggregated output can be precisely
controlled. For example, in systems like RAPPOR [EPK14], each user samples
noise from a well-known distribution and adds it to their input before
submitting to the aggregation server. The aggregation server then adds up the
noisy inputs, and because it knows the distribution from whence the noise was
sampled, it can estimate the true sum with reasonable precision.

Differentially private systems like RAPPOR are easy to deploy and provide a
useful guarantee. On its own, however, DP falls short of the strongest privacy
property one could hope for. Specifically, depending on the "amount" of noise a
client adds to its input, it may be possible for a curious aggregator to make a
reasonable guess of the input's true value. Indeed, the more noise the clients
add, the less reliable will be the server's estimate of the output. Thus systems
employing DP techniques alone must strike a delicate balance between privacy and
utility.

The ideal goal for a privacy-preserving measurement system is that of secure
multi-party computation: No participant in the protocol should learn anything
about an individual input beyond what it can deduce from the aggregate. In this
document, we describe Verifiable Distributed Aggregation Functions (VDAFs) as a
general class of protocols that achieve this goal.

VDAF schemes achieve their privacy goal by distributing the computation of the
aggregate among a number of non-colluding aggregation servers. As long as a
subset of the servers executes the protocol honestly, VDAFs guarantee that no
input is ever accessible to any party besides the client that submitted it. At
the same time, VDAFs are "verifiable" in the sense that malformed inputs that
would otherwise garble the output of the computation can be detected and removed
from the set of inputs.

The cost of achieving these security properties is the need for multiple servers
to participate in the protocol, and the need to ensure they do not collude to
undermine the VDAF's privacy guarantees.  Recent implementation experience has
shown that practical challenges of coordinating multiple servers can be
overcome.  The Prio system [CGB17] (essentially a VDAF) has been deployed in
systems supporting hundreds of millions of users: The Mozilla Origin Telemetry
project [OriginTelemetry] and the Exposure Notification Private Analytics
collaboration among the Internet Security Research Group (ISRG), Google, Apple,
and others [ENPA].

The VDAF abstraction laid out in {{vdaf}} represents a class of multi-party
protocols for privacy-preserving measurement proposed in the literature. These
protocols vary in their operational and security considerations, sometimes in
subtle but consequential ways. This document therefore has two important goals:

 1. Providing applications like {{?I-D.draft-gpew-priv-ppm}} with a simple,
    uniform interface for accessing privacy-preserving measurement schemes, and
    documenting relevant operational and security bounds for that interface:

    1. General patterns of communications among the various actors involved in
       the system (clients, aggregators, and measurement collectors);
    1. Capabilities of a malicious coalition of servers attempting divulge
       information about client inputs; and
    1. Conditions that are necessary to ensure that malicious clients cannot
       corrupt the computation.

 1. Providing cryptographers with design criteria that allow new constructions
    to be easily used by applications.

This document also specifies two concrete VDAF schemes, each based on a protocol
from the literature.

* The aforementioned Prio system [CGB17] allows for the privacy-preserving
  computation of a variety aggregate statistics. The basic idea underlying Prio
  is fairly simple:
  1. Each client shards its input into a sequence of additive shares and
     distributes the shares among the aggregation servers.
  1. Next, each server adds up its shares locally, resulting in an additive
     share of the aggregate.
  1. Finally, the aggregators combine their additive shares to obtain the final
     aggregate.

  The difficult part of this system is ensuring that the servers hold shares of
  a valid input, e.g., the input is an integer in a specific range. Thus Prio
  specifies a multi-party protocol for accomplishing this task.

  In {{prio3}} we describe `prio3`, a VDAF that follows the same overall
  framework as the original Prio protocol, but incorporates techniques
  introduced in [BBCGGI19] that result in significant performance gains.

* More recently, Boneh et al. [BBCGGI21] described a protocol called Poplar for
  solving the `t`-heavy-hitters problem in a privacy-preserving manner. Here
  each client holds a bit-string of length `n`, and the goal of the aggregation
  servers is to compute the set of inputs that occur at least `t` times. The
  core primitive used in their protocol is a generalization of a Distributed
  Point Function (DPF) [GI14] that allows the servers to "query" their DPF
  shares on any bit-string of length shorter than or equal to `n`. As a result
  of this query, each of the servers has an additive share of a bit indicating
  whether the string is a prefix of the client's input. The protocol also
  specifies a multi-party computation for verifying that at most one string
  among a set of candidates is a prefix of the client's input.

  In {{poplar1}} we describe a VDAF called `poplar1` that implements this
  functionality.

The remainder of this document is organized as follows: {{overview}} gives a
brief overview of VDAFs; {{vdaf}} defines the syntax for VDAFs; {{prelim}}
defines various functionalities that are common to our constructions; {{poplar1}}
describes the `poplar1` construction; {{prio3}} describes the `prio3` construction;
and {{security}} enumerates the security considerations for VDAFs.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Algorithms in this document are written in Python 3. Type hints are used to
define input and output types. Function parameters without type hints implicitly
have type `Bytes`, an arbitrary byte string. A fatal error in a program (e.g.,
failure to parse one of the function parameters) is usually handled by raising
an exception.

Some common functionalities:

* `zeros(len: Unsigned) -> Bytes` returns an array of zero bytes. The length of
  `output` MUST be `len`.

* `gen_rand(len: Unsigned) -> Bytes` returns an array of random bytes. The
  length of `output` MUST be `len`.

* `byte(int: Unsigned) -> Bytes` returns the representation of `int` as a byte
  string. The value of `int` MUST be in range `[0,256)`.

* `I2OSP` and `OS2IP` from {{!RFC8017}}, which are used, respectively, to
  convert a non-negative integer to a byte string and convert a byte string to a
  non-negative integer.

# Overview

In a VDAF-based private measurement system, we distinguish three types of
actors: Clients, Aggregators, and Collectors.  The overall flow of the
measurement process is as follows:

* Clients are configured with public parameters for a set of aggregators.
* To submit an individual measurement, a client shards the measurement into
  "input shares" and sends one input share to each Aggregator.
* The aggregators verify the validity of the input shares, producing a set of
  "output shares".
    * Output shares are in one-to-one correspondence with the input shares.
    * Just as each Aggregator receives one input share of each input, at the end
      of the validation process, each aggregator holds one output share.
    * In most VDAFs, aggregators will need to exchange information among
      themselves as part of the validation process.
* Each aggregator combine the output shares across inputs in the batch to
  compute "aggregate shares", i.e., shares of the desired aggregate result.
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
validation of client inputs.  Thus clients trust Aggregators not to collude
(typically it is required that at least one Aggregator is honest), and
Collectors trust Aggregators to properly verify Client inputs.

Within the bounds of the non-collusion requirements of a given VDAF instance, it
is possible for the same entity to play more than one role.  For example, the
Collector could also act as an Aggregator, effectively using the other
Aggregators to augment a basic client-server protocol.

In this document, we describe the computations performed by the actors in this
system.  It is up to applications to arrange for the required information to be
delivered to the proper actors in the proper sequence.  In general, we assume
that all communications are confidential and mutually authenticated, with the
exception that Clients submitting measurements may be anonymous.

# Definition of VDAFs {#vdaf}

A concrete VDAF specifies the algorithms involved in evaluating an aggregation
function across a batch of inputs. This section specifies the interfaces of
these algorithms as they would be exposed to applications.

The overall execution of a VDAF comprises the following steps:

* Setup - Generating shared parameters for the aggregators
* Sharding - Computing input shares from an individual measurement
* Preparation - Conversion and verification of input shares to output shares
  compatible with the aggregation function being computed
* Aggregation - Combining a sequence of output shares into an aggregate share
* Unsharding - Combining a sequence of aggregate shares into an aggregate result

The setup algorithm is performed once for a given collection of Aggregators.
Sharding and preparation are done once per measurement input.  Aggregation and
unsharding are done over a batch of inputs (more precisely, over the output
shares recovered from those inputs).

Note that the preparation step performs two functions: Verification and
conversion.  Conversion translates input shares into output shares that are
compatible with the aggregation function.  Verification ensures that aggregating
the recovered output shares will not lead to a garbled aggregate result.

<!--
For some VDAFs, like `prio3` ({{prio3}}) or `poplar1` ({{poplar1}}), the output shares
are recovered first, then validated. For other protocols, like Prio+ [AGJOP21],
there is no explicit verification step.
-->

The remainder of this section defines the VDAF interface in terms of an abstract
base class `Vdaf`. This class defines the set of methods and attributes a
concrete VDAF must provide. The attributes are listed in [{vdaf-param}}; the
methods are defined in the subsections that follow.


| Parameter          | Description              |
|:-------------------|:-------------------------|
| `ROUNDS`      | Number of rounds of communication during the preparation phase ({{sec-vdaf-prepare}}) |
| `SHARES`      | Number of input shares into which each measurement is sharded ({{sec-vdaf-shard}}) |
| `Measurement` | Type of each measurement      |
| `PublicParam` | Type of public parameter used by the Client during the sharding phase ({{sec-vdaf-shard}}) |
| `VerifyParam` | Type of verification parameter used by each Aggregator during the preparation phase ({{sec-vdaf-prepare}}) |
| `AggParam`    | Type of aggregation parameter |
| `Prep`        | State of each Aggregator during the preparation phase ({{sec-vdaf-prepare}}) |
| `OutShare`    | Type of each output share     |
| `AggShare`    | Type of each aggreagte share  |
| `AggResult`   | Type of the aggreagte result  |
{: #vdaf-param title="Constants and types defined by each concrete VDAF."}

## Setup {#sec-vdaf-setup}

Before execution of the VDAF can begin, it is necessary to distribute long-lived
parameters to the Client and Aggregators. The long-lived parameters are
generated by the following algorithm:

* `Vdaf.setup() -> (PublicParam, Vec[VerifyParam])` is the randomized setup
  algorithm used to generate the public parameter used by the Clients and the
  verification parameters used by the Aggregators. The length of the latter MUST
  be equal to `SHARES`. In general, an Aggregator's verification parameter is
  considered secret and MUST NOT be revealed to the Clients, Collector or other
  Aggregators. The parameters MAY be reused across multiple VDAF evaluations.
  See {{security}} for a discussion of the security implications this has
  depending on the threat model.

## Sharding {#sec-vdaf-shard}

In order to protect the privacy of its measurements, a VDAF client splits its
measurements into "input shares".  The `measurement_to_input_shares` method is
executed by the client to produce these shares.  One share is sent to each
aggregator.

* `Vdaf.measurement_to_input_shares(public_param: PublicParam, input:
  Measurement) -> Vec[Bytes]` is the randomized input-distribution algorithm run
  by each Client. It consumes the public parameter and input measurement and
  produces a sequence of input shares, one for each Aggregator. The length of
  the output MUST be `SHARES`.

~~~~
    Client
    ======

    measurement
      |
      V
    +----------------------------------------------+
    | measurement_to_input_shares                  |
    +----------------------------------------------+
      |              |              ...  |
      V              V                   V
     input_share_0  input_share_1       input_share_[SHARES-1]
      |              |              ...  |
      V              V                   V
    Aggregator 0   Aggregator 1        Aggregator SHARES-1
~~~~
{: #shard-flow title="The Client divides its measurement input into input shares
and distributes them to the Aggregators."}

> CP The `public_param` is intended to allow for protocols that require the
> Client to use a public key for sharding its measurement. When rotating the
> `verify_param` for such a scheme, it would be necessary to also update the
> `public_param` with which the clients are configured. For PPM it would be nice
> if we could rotate the `verify_param` without also having to update the
> clients. We should consider dropping this at some point.

## Preparation {#sec-vdaf-prepare}

To recover and verify output shares, the Aggregators interact with one another
over `ROUNDS` rounds. Prior to each round, each Aggregator constructs an
outbound message. Next, the sequence of outbound messages produced by the
Aggregators is combined into a single message, called a "preparation message".
(Each of the outbound messages are called "preparation-message shares".)
Finally, the preparation message is distributed to the Aggregators to begin the
next round.

An aggregator begins the first round with its input share and it begins each
subsequent round with the previous preparation message. The aggregator's output
in the last round is its output share and its output in each of the preceding
rounds is a preparation-message share.

This process involves a value called the "aggregation parameter" used to map the
input shares to output shares. The Aggregators need to agree on this parameter
before they can begin preparing inputs for aggregation.

~~~~
    Aggregator 0   Aggregator 1        Aggregator SHARES-1
    ============   ============        ===================

    input_share_0  input_share_1       input_share_[SHARES-1]
      |              |              ...  |
      V              V                   V
    +-----------+  +-----------+       +-----------+
    | prep_init |  | prep_init |       | prep_init |
    +-----------+  +------------+      +-----------+
      |              |              ...  |             \
      V              V                   V             |
    +-----------+  +-----------+       +-----------+   |
    | prep_next |  | prep_next |       | prep_next |   |
    +-----------+  +-----------+       +-----------+   |
      |              |              ...  |             |
      V              V                   V             | x ROUNDS
    +----------------------------------------------+   |
    | prep_shares_to_prep                          |   |
    +----------------------------------------------+   |
                     |                                 |
      +--------------+-------------------+             |
      |              |              ...  |             |
      V              V                   V             /
     ...            ...                 ...
      |              |                   |
      V              V                   V
    +-----------+  +-----------+       +-----------+
    | prep_next |  | prep_next |       | prep_next |
    +-----------+  +-----------+       +-----------+
      |              |              ...  |
      V              V                   V
    out_share_0    out_share_1         out_share_[SHARES-1]
~~~~
{: #prep-flow title="VDAF preparation process on the input shares for a single
measurement. At the end of the computation, each Aggregator holds an output
share or an error."}

To facilitate the preparation process, a concerete VDAF implements the following
class methods:

* `Vdaf.prep_init(verify_param: VerifyParam, agg_param: AggParam, nonce: Bytes,
  input_share: Bytes) -> Prep` is the deterministic preparation-state
  initialization algorithm run by each Aggregator to begin processing its input
  share into an output share. Its inputs are the aggregator's verification
  parameter (`verify_param`), the aggregation parameter (`agg_param`), the nonce
  provided by the environment (`nonce`, see {{run-vdaf}}), and one of the input
  shares generated by the client (`input_share`). Its output is the Aggregator's
  initial preparation state.

* `Vdaf.prep_next(prep: Prep, inbound: Optional[Bytes]) -> Union[Tuple[Prep,
  Bytes], OutShare]` is the deterministic preparation-state update algorithm run
  by each Aggregator. It updates the Aggregator's preparation state (`prep`) and
  returns either its next preparation state and its message share for the
  current round or, if this is the last round, its output share. An exception is
  raised if a valid output share could not be recovered. The input of this
  algorithm is the inbound preparation message or, if this is the first round,
  `None`.

* `Vdaf.prep_shares_to_prep(agg_param: AggParam, prep_shares: Vec[Bytes]) ->
  Bytes` is the deterministc preparation-message preprocessing algorithm. It
  combines the preperation-message shares generated by the Aggregators in the
  previous round into the pepration message consumed by each in the next round.

In effect, each Aggregator moves through a linear state machine with `ROUNDS+1`
states.  The Aggregator enters the first state on using the initialization
algorithm, and the update algorithm advances the Aggregator to the next state.
Thus, in addition to defining the number of rounds (`ROUNDS`), a VDAF instance
defines the state of the Aggregator after each round.

> TODO Consider how to bake this "linear state machine" condition into the
> syntax. Given that Python 3 is used as our pseudocode, it's easier to specify
> the preparation state using a class.

The preparation-state update accomplishes two tasks that are essential to most
schemes: recovery of output shares from the input shares, and a multi-party
computation carried out by the Aggregators to ensure that their output shares
are valid. The VDAF abstraction boundary is drawn so that an Aggregator only
recovers an output share if it is deemed valid (at least, based on the
Aggregator's view of the protocol). Another way to draw this boundary would be
to have the Aggregators recover output shares first, then verify that they are
valid. However, this would allow the possibility of misusing the API by, say,
aggregating an invalid output share. Moreover, in protocols like Prio+
{{AGJOP21}} based on oblivious transfer, it is necessary for the Aggregators to
interact in order to recover output shares at all.

Note that it is possible for a VDAF to specify `ROUNDS == 0`, in which case
each Aggregator runs the preparation-state update algorithm once and immediately
recovers its output share without interacting with the other Aggregators.
However, most, if not all, constructions will require some amount of interaction
in order to ensure validity of the output shares (while also maintaining
privacy).

> OPEN ISSUE Depending on what we do for issue#20, we may end up needeing to
> revise the above paragraph.

## Aggregation {#sec-vdaf-aggregate}

Once an Aggregator holds validated output shares for a batch of measurements
(where batches are defined by the application), it combines them into a share of
the desired aggregate result.  This algorithm is performed locally at each
Aggregator, without communication with the other Aggregators.

* `Vdaf.out_shares_to_agg_share(agg_param: AggParam, output_shares:
  Vec[OutShare]) -> agg_share: AggShare` is the deterministic aggregation
  algorithm. It is run by each Aggregator over the output shares it has computed
  over a batch of measurement inputs.

~~~~
    Aggregator 0    Aggregator 1        Aggregator SHARES-1
    ============    ============        ===================

    out_share_0_0   out_share_1_0       out_share_[SHARES-1]_0
    out_share_0_1   out_share_1_1       out_share_[SHARES-1]_1
    out_share_0_2   out_share_1_2       out_share_[SHARES-1]_2
         ...             ...                     ...
    out_share_0_B   out_share_1_B       out_share_[SHARES-1]_B
      |               |                   |
      V               V                   V
    +-----------+   +-----------+       +-----------+
    | out2agg   |   | out2agg   |   ... | out2agg   |
    +-----------+   +-----------+       +-----------+
      |               |                   |
      V               V                   V
    agg_share_0     agg_share_1         agg_share_[SHARES-1]
~~~~
{: #agg-flow title="Aggregation of output shares. `B` indicates the number of
measurements in the batch."}

For simplicity, we have written this algorithm and the unsharding algorithm
below in "one-shot" form, where all shares for a batch are provided at the same
time.  Some VDAFs may also support a "streaming" form, where shares are
processed one at a time.

## Unsharding {#sec-vdaf-unshard}

After the Aggregators have aggregated a sufficient number of output shares, each
sends its aggregate share to the Collector, who runs the following algorithm to
recover the following output:

* `Vdaf.agg_shares_to_result(agg_param: AggParam, agg_shares:
  Vec[AggShare]) -> AggResult` is run by the Collector in order to compute the
  aggregate result from the Aggregators' shares. The length of `agg_shares` MUST
  be `SHARES`. This algorithm is deterministic.

~~~~
    Aggregator 0    Aggregator 1        Aggregator SHARES-1
    ============    ============        ===================

    agg_share_0     agg_share_1         agg_share_[SHARES-1]
      |               |                   |
      V               V                   V
    +-----------------------------------------------+
    | agg_shares_to_result                          |
    +-----------------------------------------------+
      |
      V
    agg_result

    Collector
    =========
~~~~
{: #unshard-flow title="Computation of the final aggregate result from aggregate
shares."}

> QUESTION Maybe the aggregation algorithms should be randomized in order to
> allow the Aggregators (or the Collector) to add noise for differential
> privacy. (See the security considerations of {{?I-D.draft-gpew-priv-ppm}}.) Or
> is this out-of-scope of this document?

## Execution of a VDAF {#execution}

Executing a VDAF involves the concurrent evaluation of the VDAF on individual
inputs and aggregation of the recovered output shares. This is captured by the
following example algorithm:

~~~
def run_vdaf(Vdaf,
             agg_param: Vdaf.AggParam,
             nonces: Vec[Bytes],
             measurements: Vec[Vdaf.Measurement]):
    # Distribute long-lived parameters.
    (public_param, verify_params) = Vdaf.setup()

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        # Each Client shards its input into shares.
        input_shares = Vdaf.measurement_to_input_shares(public_param,
                                                        measurement)

        # Each Aggregator initializes its preparation state.
        prep_states = []
        for j in range(Vdaf.SHARES):
            state = Vdaf.prep_init(verify_params[j],
                                   agg_param,
                                   nonce,
                                   input_shares[j])
            prep_states.append(state)

        # Aggregators recover their output shares.
        inbound = None
        for i in range(Vdaf.ROUNDS+1):
            outbound = []
            for j in range(Vdaf.SHARES):
                out = Vdaf.prep_next(prep_states[j], inbound)
                if i < Vdaf.ROUNDS:
                    (prep_states[j], out) = out
                outbound.append(out)
            # This is where we would send messages over the network
            # in a distributed VDAF computation.
            if i < Vdaf.ROUNDS:
                inbound = Vdaf.prep_shares_to_prep(agg_param,
                                                   outbound)

        # The final outputs of prepare phasre are the output shares.
        out_shares.append(outbound)

    # Each Aggregator aggregates its output shares into an aggregate
    # share.
    agg_shares = []
    for j in range(Vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = Vdaf.out_shares_to_agg_share(agg_param,
                                                   out_shares_j)
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate.
    return Vdaf.agg_shares_to_result(agg_param, agg_shares)
~~~
{: #run-vdaf title="Execution of a VDAF."}

The inputs to this algorithm are the aggregation parameter `agg_param`, a list
of nonces `nonces`, and a batch of Client inputs `input_batch`. The aggregation
parameter is chosen by the Aggregators prior to executing the VDAF. This
document does not specify how the nonces are chosen, but some of our security
considerations require that the nonces be unique for each VDAF evaluation. See
{{security}} for details.

Another important question this document leaves out of scope is how a VDAF is to
be executed by Aggregators distributed over a real network. Algorithm `run_vdaf`
prescribes the protocol's execution in a "benign" environment in which there is
no adversary and messages are passed among the protocol participants over secure
point-to-point channels. In reality, these channels need to be instantiated by
some "wrapper protocol", such as {{I-D.draft-gpew-priv-ppm}} that implements
suitable cryptographic functionalities. Moreover, some fraction of the
Aggregators (or Clients) may be malicious and diverge from their prescribed
behaviors. {{security}} describes the execution of the VDAF in various
adversarial environments and what properties the wrapper protocol needs to
provide in each.

<!--
## VDAFs in the Literature

* Prio [CGB17] defines the composition of a linear secret sharing scheme and an
  affine-aggregatable encoding of a statistic.

* A special case of zero-knowledge proofs over distributed data [BBCGGI19] in
  which the client speaks once.

* The composition of an incremental distributed point function and the
  secure-sketching protocol for subset histograms defined in [BBCGGI21].

* Prio+ [AGJOP21] has the client upload XOR shares and then has the servers
  convert them to additive shares over a number of rounds.
-->

# Preliminaries {#prelim}

This section describes the primitives that are common to the VDAFs specified in
this document.

## Finite Fields {#field}

Both `prio3` and `poplar1` use finite fields with characteristic 1, i.e., the
field `GF(p)` for some prime `p`. Finite field elements are represented by a
class `Field` with the following associated parameters:

* `ENCODED_SIZE: Unsigned` is the number of bytes used to encode a field element
  as a byte string.

A concrete `Field` also implements the following class methods:

* `Field.zeros(length: Unsigned) -> output: Vec[Field]` returns a vector of
  zeros. The length of `output` MUST be `length`.

* `Field.rand_vec(length: Unsigned) -> output: Vec[Field]` returns a vector of
  random field elements. The length of `output` MUST be `length`.

A field element is an instance of a concrete `Field`. The concrete class defines
the usual arithmetic operations on field elements. In addition, it defines the
following instance method for converting a field element to an unsigned integer:

* `elem.as_unsigned() -> Unsigned` returns the integer representation of
  field element `elem`.

Likewise, each concrete `Field` implements a constructor for coverting an
unsigned integer into a field element:

* `Field(integer: Unsigned)` returns `integer` represented as a field element.

Finally, each concerete `Field` has two derived class methods, one for encoding
a vector of field elements as a byte string and another for decoding a vector of
field elements.

~~~
def encode_vec(Field, vec: Vec[Field]) -> Bytes:
    encoded = Bytes()
    for x in vec:
        encoded += I2OSP(x.as_unsigned(), Field.ENCODED_SIZE)
    return encoded

def decode_vec(Field, encoded: Bytes) -> Vec[Field]:
    L = Field.ENCODED_SIZE
    if len(encoded) % L != 0:
        raise ERR_DECODE

    vec = []
    for i in range(0, len(encoded), L):
        encoded_x = encoded[i:i+L]
        x = Field(OS2IP(encoded_x))
        vec.append(x)
    return vec
~~~
{: #field-derived-methods title="Derived class methods for finite fields."}

### Inner product of Vectors

The following method is defined for computing the inner product of two vectors:

```
def inner_product(left: Vec[Field], right: Vec[Field]) -> Field:
    result = Field(0)
    for (x, y) in zip(left, right):
        result += x * y
    return result
```

### Parameters

> TODO: Pick field parameters and specify them here. See issue#22.

## Pseudorandom Generators {#prg}

A pseudorandom generator (PRG) is used to expand a short, (pseudo)random seed
into a long string of pseudorandom bits. A PRG suitable for this document
implements the interface specified in this section. Concrete constructions are
described in {{prg-constructions}}.

PRGs are defined by a class `Prg` with a single parameter:

* `SEED_SIZE: Unsigned` is the size of the input seed.

A concrete `Prg` implements the following class method:

* `Prg.expand(seed: Bytes, info: Bytes, length: Unsigned) -> Bytes` derives a
  byte string from the given seed and info string. The length of the output MUST
  be `length`.

> TODO Specify a generic method for mapping the PRG output to a sequence of
> field elements.

### Constructions {#prg-constructions}

> TODO

# prio3 {#prio3}

> NOTE This construction has not undergone significant security analysis.

This section describes a VDAF suitable for the following data aggregation task.
Each Client measurement is encoded as a vector over a finite field, and the
aggregate is computed by summing the vectors element-wise. Validity is defined
by an arithmetic circuit `C` that takes as input a vector of field elements `x`:
if `C(x) == 0`, then we say that `x` is valid; otherwise, we say that `x` is
invalid.  A number of useful measurement types can be defined this way:

* Simples statistics, like sum, average, and standard deviation;
* Estimation of quantiles, via a histogram; and
* Linear regression.

This VDAF does not have an aggregation parameter. Instead, the output share is
derived from an input share by applying a fixed map. See {{poplar1}} for an
example of a VDAF that makes meaningful use of the aggregation parameter.

While the construction is derived from the original Prio system {{CGB17}},
`prio3` takes advantage of optimizations described later in {{BBCGGI19}} that
improve communication complexity significantly. The etymology of the term
`prio3` is that it descends from the original Prio construction. A second
iteration was deployed in the {{ENPA}} system, and like the VDAF described here,
the ENPA system was built from techniques introduced by {{BBCGGI19}}. However,
that system was specialized for a particular measurement type. The goal of
`prio3` is to provide the same level of generality as the original system.

The way `prio3` ensures privacy is quite simple: the Client shards its encoded
input vector `x` into a number of additive secret shares, one for each
Aggregator. Each Aggregator sums up its vector shares locally, and once enough
shares have been aggregated, sends its share of the result to the Collector, who
recovers the aggregate result by adding up the vectors.

The main problem that needs to be solved is to verify that the additive shares
generated by the Client add up to a valid input `x`, i.e., that `C(x)=0`. The
solution devised by {{BBCGGI19}} uses what they call a zero-knowledge proof
system on distributed data. Viewing the Client as the prover and the Aggregators
as the (distributed) verifier, the goal is to devise a protocol by which the
Client convinces the Aggregators that they hold secret shares of a valid input,
without revealing the input itself.

The core tool for accomplishing this task is a refinement of Probabilistically
Checkable Proof (PCP) systems called a Fully Linear Proof (FLP) system.  We
describe FLPs in detail below. Briefly, the Client generates a "proof" of its
input's validity and distributes additive shares of the proof among the
Aggregators. Each Aggregator then performs a computation on its input share and
proof share locally and sends the result to the other Aggregators. Combining the
exchanged messages allows each Aggregator to decide if it holds a share of a valid input.

`prio3` can be viewed as a transformation of a particular class of FLP systems
into a VDAF. The next section specified the syntax of suitable FLPs in detail.
The transformation is given in {{prio3-construction}}.

## Fully Linear Proof (FLP) Systems {#flp}

Conceptually, an FLP system is a two-party protocol executed by a prover and a
verifier. In actual use, however, the prover's computation is carried out by the
Client, and the verifier's computation is distributed among the Aggregators.
(More on this in {{prio3-construction}}.)

As usual, we will describe the interface implemented by a concrete FLP in terms
of an abstraction base class `Flp` that specifies the set of methods and
parameters a concrete FLP must provide.

The parameters define by an FLP are listed in {{flp-param}}.

First, a concrete FLP defines the following constants:

| Parameter        | Description              |
|:-----------------|:-------------------------|
| `PROVE_RAND_LEN` | Length of the prover randomness, the number of random field elements consumed by the prover when generating a proof |
| `QUERY_RAND_LEN` | Length of the query randomness, the number of random field elements consumed by the verifier |
| `JOINT_RAND_LEN` | Length of the joint randomness, the number of random field elements consuemd by both the prover and verifier |
| `INPUT_LEN`      | Length of the encoded measurement ({{flp-encode}}) |
| `OUTPUT_LEN`     | Length of the aggregtrable output ({{flp-encode}}) |
| `PROOF_LEN`      | Length of the proof |
| `VERIFIER_LEN`   | Length of the verifier message generated by quering the input and proof |
| `Field`          | The finite field for which the FLP is defined ({{field}}) |
{: #flp-param title="Constants and types defined by each concrete FLP."}

An FLP specifies the following algorithms for generating and verifying proofs of
validity for encoded inputs (encoding is described below in {{flp-encode}}):

* `Flp.prove(input: Vec[Field], prove_rand: Vec[Field], joint_rand: Vec[Field])
  -> Vec[Field]` is the deterministic proof-generation algorithm run by the
  prover. Its inputs are the encoded input, the "prover randomness"
  `prove_rand`, and the "joint randomness" `joint_rand`. The proof randomness is
  used only by the prover, but the joint randomness is shared by both the prover
  and verifier. Type `Field` is a finite field as defined in {{field}}.

* `Flp.query(input: Vec[Field], proof: Vec[Field], query_rand: Vec[Field],
  joint_rand: Vec[Field]) -> Vec[Field]` is the query-generation
  algorithm run by the verifier. This is is used to "query" the input and proof.
  The result of the query (i.e., the output of this function) is called the
  "verifier message". In addition to the input and proof, this algorithm takes
  as input the query randomness `query_rand` and the joint randomness
  `joint_rand`. The former is used only by the verifier, but the latter is the
  same randomness used by the prover.

* `Flp.decide(verifier: Vec[Field]) -> Bool` is the deterministic decision
  algorithm run by the verifier. It takes as input the verifier message and
  outputs a boolean indicating if the input from whence it was generated is
  valid.

Our application requires that the FLP is "fully linear" in the sense defined in
{{BBCGGI19}}. This property amounts essentially to a syntactic restriction on
the proof systeem. As a practical matter, what this property implies is that the
query-generation algorithm can be run by each Aggregator locally on its share of
the input and proof, and the results can be combined to recover the verifier
message. In the remainder, the result generated by an aggregator will be
referred to as its "verifier share".

An FLP is executed by the prover and verifier as follows:

~~~
def run_flp(Flp, inp: Vec[Flp.Field], num_shares: Unsigned):
    joint_rand = Flp.Field.rand_vec(Flp.JOINT_RAND_LEN)
    prove_rand = Flp.Field.rand_vec(Flp.PROVE_RAND_LEN)
    query_rand = Flp.Field.rand_vec(Flp.QUERY_RAND_LEN)

    # Prover generates the proof.
    proof = Flp.prove(inp, prove_rand, joint_rand)

    # Verifier queries the input and proof.
    verifier = Flp.query(
        inp, proof, query_rand, joint_rand, num_shares)

    # Verifier decides if the input is valid.
    return Flp.decide(verifier)
~~~
{: #run-flp title="Execution of an FLP."}

The proof system is constructed so that, if `input` is a valid input, then
`run_flp(Flp,. input)` always returns `True`. On the other hand, if `input` is
invalid, then as long as `joint_rand` and `query_rand` are generated uniform
randomly, the output is `False` with overwhelming probability. In addition, the
proof system is designed so that the verifier message leaks nothing about the
input (in an information theoretic sense). See Definition 3.9 from {{BBCGGI19}}
for details.

We remark that {{BBCGGI19}} defines a much larger class of fully linear proof
systems than we consider here. In particular, what is called an "FLP" here is
called a 1.5-round, public-coin, interactive oracle proof system in their paper.

### Encoding the Input {#flp-encode}

The type of measurement being aggregated is defined by the FLP. Hence, the FLP
also specifies a method of encoding raw measurements as a vector of field
elements:

* `Flp.encode(measurement: Measurement) -> Vec[Field]` encodes a raw measurement
  as a vector of field elements. The return value MUST be of length `INPUT_LEN`.
  An error is raised if the measurement cannot be represented as a valid input.

In addition, for some FLPs, the encoded input includes redundant field elements
that are useful for checking the proof, but which are not needed after the proof
has been checked. Thus the FLP defines an algorithm for truncating the input to
the length of the aggregated output:

* `Flp.truncate(input: Vec[Field]) -> Vec[Field]` maps an encoded input to an
  aggregable output. The length of the input MUST be `INPUT_LEN` and the length
  of the output MUST be `OUTPUT_LEN`.

The need for the truncation method arises from the observation that some FLPs
encode redundancy into the input that is used for proof generation; and once the
proof is checked, the redundancy can be removed before aggregating. An example
is the "integer sum" data type from {{CGB17}} in which an integer in range `[0,
2^k)` is encoded as a vectot of `k` field elements. Taken together, these two
functionalities correspond roughly to the notion of Affine-aggregatable
encodings (AFEs) from {{CGB17}}.

## Construction {#prio3-construction}

This section specifies `Prio3`, an implementation of the `Vdaf` interface
({{vdaf}}). It has two generic parameters: an `Flp` ({{flp}}) and a `Prg`
({{prg}}). The associated constants and types required by the `Vdaf` interface
are defined in {{prio3-param}}. The methods required for sharding, preparation,
aggregation, and unsharding are desribed in the remaining subsections.

| Parameter     | Value                    |
|:--------------|:-------------------------|
| `ROUNDS`      | `1`                      |
| `SHARES`      | in range `[2, 255)`      |
| `Measurement` | `Flp.Measurement`        |
| `PublicParam` | `None`                   |
| `VerifyParam` | `Tuple[Unsigned, Bytes]` |
| `AggParam`    | `None`                   |
| `Prep`        | `Tuple[Vec[Flp.Field], Optional[Bytes], Bytes]` |
| `OutShare`    | `Vec[Flp.Field]`         |
| `AggShare`    | `Vec[Flp.Field]`         |
| `AggResult`   | `Vec[Unsigned]`          |
{: #prio3-param title="Associated parameters for the prio3 VDAF."}

### Setup

The setup algorithm generates a symmetric key shared by all of the Aggregators.
The key is used to derive unique joint randomness for the FLP query-generation
algorithm run by the aggregators during preparation. An Aggregator's
verification paramter also includes its "ID", a a unique integer in `[0,
SHARES)`

~~~
def setup(Prio3):
    k_query_init = gen_rand(Prio3.Prg.SEED_SIZE)
    verify_param = [(j, k_query_init) for j in range(Prio3.SHARES)]
    return (None, verify_param)
~~~
{: #prio3-eval-setup title="The setup algorithm for prio3."}

### Sharding

Recall from {{flp}} that the syntax for FLP systems calls for "joint randomness"
shared by the prover (i.e., the Client) and the verifier (i.e., the
Aggregators). VDAFs have no such notion. Instead, the Client derives the joint
randomness from its input in a way that allows the Aggregators to reconstruct it
from their input shares. (This idea comes from Section 6.2.3 of {{BBCGGI19}}.)

The input-distribution algorithm involves the following steps:

1. Encode the Client's raw measurement as an input for the FLP
1. Shard the input into a sequence of input shares
1. Derive the joint randomness from the input shares
1. Run the FLP proof-generation algorithm using the joint randomness and prover
   randomness generated locally
1. Shard the proof into a sequence of input shares

The input and proof shares of one Aggregator (below we call it the "leader") are
vectors of field elements. The shares of the other aggregators (below we call
them the "helpers") are represented instead by PRG seeds, which are expanded
into vectors of field elements of the required length. (See {{prg}}.)

This algorithm also makes use of a pair of helper functions for encoding the
leader share and helper share. These are called `encode_leader_share` and
`encode_helper_share` respectively and they are described in
{{prio3-helper-functions}}.

~~~
def measurement_to_input_shares(Prio3, _public_param, measurement):
    inp = Prio3.Flp.encode(measurement)
    k_joint_rand = zeros(Prio3.Prg.SEED_SIZE)

    # Generate input shares.
    leader_input_share = inp
    k_helper_input_shares = []
    k_helper_blinds = []
    k_helper_hints = []
    for j in range(Prio3.SHARES-1):
        k_blind = gen_rand(Prio3.Prg.SEED_SIZE)
        k_share = gen_rand(Prio3.Prg.SEED_SIZE)
        helper_input_share = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_share,
            b"input share",
            Prio3.Flp.INPUT_LEN
        )
        leader_input_share = vec_sub(leader_input_share,
                                     helper_input_share)
        encoded = Prio3.Flp.Field.encode_vec(helper_input_share)
        k_hint = Prio3.Prg.derive(k_blind, byte(j+1) + encoded)
        k_joint_rand = xor(k_joint_rand, k_hint)
        k_helper_input_shares.append(k_share)
        k_helper_blinds.append(k_blind)
        k_helper_hints.append(k_hint)
    k_leader_blind = gen_rand(Prio3.Prg.SEED_SIZE)
    encoded = Prio3.Flp.Field.encode_vec(leader_input_share)
    k_leader_hint = Prio3.Prg.derive(k_leader_blind,
                                     byte(0) + encoded)
    k_joint_rand = xor(k_joint_rand, k_leader_hint)

    # Finish joint randomness hints.
    for j in range(Prio3.SHARES-1):
        k_helper_hints[j] = xor(k_helper_hints[j], k_joint_rand)
    k_leader_hint = xor(k_leader_hint, k_joint_rand)

    # Generate the proof shares.
    prove_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        gen_rand(Prio3.Prg.SEED_SIZE),
        b"prove rand",
        Prio3.Flp.PROVE_RAND_LEN
    )
    joint_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        k_joint_rand,
        b"joint rand",
        Prio3.Flp.JOINT_RAND_LEN
    )
    proof = Prio3.Flp.prove(inp, prove_rand, joint_rand)
    leader_proof_share = proof
    k_helper_proof_shares = []
    for j in range(Prio3.SHARES-1):
        k_share = gen_rand(Prio3.Prg.SEED_SIZE)
        k_helper_proof_shares.append(k_share)
        helper_proof_share = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_share,
            b"proof share",
            Prio3.Flp.PROOF_LEN
        )
        leader_proof_share = vec_sub(leader_proof_share,
                                     helper_proof_share)

    input_shares = []
    input_shares.append(Prio3.encode_leader_share(
        leader_input_share,
        leader_proof_share,
        k_leader_blind,
        k_leader_hint,
    ))
    for j in range(Prio3.SHARES-1):
        input_shares.append(Prio3.encode_helper_share(
            k_helper_input_shares[j],
            k_helper_proof_shares[j],
            k_helper_blinds[j],
            k_helper_hints[j],
        ))
    return input_shares
~~~
{: #prio3-eval-input title="Input-distribution algorithm for prio3."}

### Preparation

This section describes the process of recovering output shares from the input
shares. The high-level idea is that each Aggregators first queries its input and
proof share locally, then exchanges its verifier share with the other
Aggregators. The verifeir shares are then combined into the verifier message,
which is used by each Aggregator locally to decide whether to accept.

In addition, the Aggregators must ensure that they have all used the same joint
randomness for the query-generation algorithm. The joint randomness is generated
by a PRG seed. Each Aggregator derives an XOR secret share of this seed from its
input share and the "blind" generated by the client. This means that, before it
can run the query-generation algorithm, it must first gather the XOR secret
shares derived by the other Aggregators.

So that the Aggregators can avoid an extra round of communication, the Client
sends each Aggregator a "hint" equal to the XOR of the other Aggregators' shares
of the joint randomness key. This leaves open the possibility that the
Client cheated by, say, forcing the Aggregators to use joint randomness that
biases the proof check procedure some way in its favor. To mitigate this, the
Aggregators also check that they have all computed the same joint randomness key
before accepting their output shares. To do so, they exchange their XOR shares
of the PRG seed along with their verifier shares.

> NOTE This optimization somewhat diverges from Section 6.2.3 of {{BBCGGI19}}.
> Security analysis is needed.

The algorithms required for preparation are defined as follows. These algorithms
make use of encoding and decoding methods defined in {{prio3-helper-functions}}.

~~~
def prep_init(Prio3, verify_param, _agg_param, nonce, input_share):
    (j, k_query_init) = verify_param

    (input_share, proof_share, k_blind, k_hint) = \
        Prio3.decode_leader_share(input_share) if j == 0 else \
        Prio3.decode_helper_share(input_share)

    out_share = Prio3.Flp.truncate(input_share)

    k_query_rand = Prio3.Prg.derive(k_query_init, byte(255) + nonce)
    query_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        k_query_rand,
        b"query rand",
        Prio3.Flp.QUERY_RAND_LEN
    )
    joint_rand, k_joint_rand, k_joint_rand_share = [], None, None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded = Prio3.Flp.Field.encode_vec(input_share)
        k_joint_rand_share = Prio3.Prg.derive(k_blind,
                                              byte(j) + encoded)
        k_joint_rand = xor(k_hint, k_joint_rand_share)
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand,
            b"joint rand",
            Prio3.Flp.JOINT_RAND_LEN
        )
    verifier_share = Prio3.Flp.query(input_share,
                                     proof_share,
                                     query_rand,
                                     joint_rand,
                                     Prio3.SHARES)

    prep_msg = Prio3.encode_prepare_message(verifier_share,
                                            k_joint_rand_share)
    return (out_share, k_joint_rand, prep_msg)

def prep_next(Prio3, prep, inbound):
    (out_share, k_joint_rand, prep_msg) = prep

    if inbound is None:
        return (prep, prep_msg)

    (verifier, k_joint_rand_check) = \
        Prio3.decode_prepare_message(inbound)

    if k_joint_rand_check != k_joint_rand or \
            not Prio3.Flp.decide(verifier):
        raise ERR_VERIFY

    return out_share

def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
    verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
    k_joint_rand_check = zeros(Prio3.Prg.SEED_SIZE)
    for encoded in prep_shares:
        (verifier_share, k_joint_rand_share) = \
            Prio3.decode_prepare_message(encoded)

        verifier = vec_add(verifier, verifier_share)

        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_joint_rand_check = xor(k_joint_rand_check,
                                     k_joint_rand_share)

    return Prio3.encode_prepare_message(verifier, k_joint_rand_check)
~~~
{: #prio3-prep-state title="Preparation state for prio3."}

### Aggregation

~~~
def out_shares_to_agg_share(Prio3, _agg_param, out_shares):
    agg_share = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
    for out_share in out_shares:
        agg_share = vec_add(agg_share, out_share)
    return agg_share
~~~
{: #prio3-out2agg title="Aggregation algorithm for prio3."}

### Unsharding

~~~
def agg_shares_to_result(Prio3, _agg_param, agg_shares):
    agg = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
    for agg_share in agg_shares:
        agg = vec_add(agg, agg_share)
    return list(map(lambda x: x.as_unsigned(), agg))
~~~
{: #prio3-agg-output title="Computation of the aggregate result for prio3."}

### Helper Functions {#prio3-helper-functions}

~~~
def encode_leader_share(Prio3,
                        input_share,
                        proof_share,
                        k_blind,
                        k_hint):
    encoded = Bytes()
    encoded += Prio3.Flp.Field.encode_vec(input_share)
    encoded += Prio3.Flp.Field.encode_vec(proof_share)
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_blind
        encoded += k_hint
    return encoded

def decode_leader_share(Prio3, encoded):
    l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.INPUT_LEN
    encoded_input_share, encoded = encoded[:l], encoded[l:]
    input_share = Prio3.Flp.Field.decode_vec(encoded_input_share)
    l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.PROOF_LEN
    encoded_proof_share, encoded = encoded[:l], encoded[l:]
    proof_share = Prio3.Flp.Field.decode_vec(encoded_proof_share)
    l = Prio3.Prg.SEED_SIZE
    k_blind, k_hint = None, None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        k_blind, encoded = encoded[:l], encoded[l:]
        k_hint, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return (input_share, proof_share, k_blind, k_hint)

def encode_helper_share(Prio3,
                        k_input_share,
                        k_proof_share,
                        k_blind,
                        k_hint):
    encoded = Bytes()
    encoded += k_input_share
    encoded += k_proof_share
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_blind
        encoded += k_hint
    return encoded

def decode_helper_share(Prio3, encoded):
    l = Prio3.Prg.SEED_SIZE
    k_input_share, encoded = encoded[:l], encoded[l:]
    input_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                            k_input_share,
                                            b"input share",
                                            Prio3.Flp.INPUT_LEN)
    k_proof_share, encoded = encoded[:l], encoded[l:]
    proof_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                            k_proof_share,
                                            b"proof share",
                                            Prio3.Flp.PROOF_LEN)
    k_blind, k_hint = None, None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        k_blind, encoded = encoded[:l], encoded[l:]
        k_hint, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return (input_share, proof_share, k_blind, k_hint)

def encode_prepare_message(Prio3, verifier, k_joint_rand):
    encoded = Bytes()
    encoded += Prio3.Flp.Field.encode_vec(verifier)
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_joint_rand
    return encoded

def decode_prepare_message(Prio3, encoded):
    l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.VERIFIER_LEN
    encoded_verifier, encoded = encoded[:l], encoded[l:]
    verifier = Prio3.Flp.Field.decode_vec(encoded_verifier)
    k_joint_rand = None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        l = Prio3.Prg.SEED_SIZE
        k_joint_rand, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return (verifier, k_joint_rand)
~~~
{: #prio3-helpers title="Helper functions required for prio3."}

# poplar1 {#poplar1}

> NOTE An implementation of this VDAF can be found
> [here](https://github.com/abetterinternet/libprio-rs/blob/main/src/vdaf/poplar1.rs).

This section specifies `poplar1`, a VDAF for the following task. Each Client holds
a `BITS`-bit string and the Aggregators hold a set of `l`-bit strings, where `l
<= BITS`. We will refer to the latter as the set of "candidate prefixes". The
Aggregators' goal is to count how many inputs are prefixed by each candidate
prefix.

This functionality is the core component of Poplar [BBCGGI21]. At a high level,
the protocol works as follows.

1. Each Clients runs the input-distribution algorithm on its `n`-bit string and
   sends an input share to each Aggregator.
2. The Aggregators agree on an initial set of candidate prefixes, say `0` and
   `1`.
3. The Aggregators evaluate the VDAF on each set of input shares and aggregate
   the recovered output shares. The aggregation parameter is the set of
   candidate prefixes.
4. The Aggregators send their aggregate shares to the Collector, who combines
   them to recover the counts of each candidate prefix.
5. Let `H` denote the set of prefixes that occurred at least `t` times. If the
   prefixes all have length `BITS`, then `H` is the set of `t`-heavy-hitters.
   Otherwise compute the next set of candidate prefixes as follows. For each `p`
   in `H`, add add `p || 0` and `p || 1` to the set. Repeat step 3 with the new
   set of candidate prefixes.

`poplar1` is constructed from an "Incremental Distributed Point Function (IDPF)", a
primitive described by [BBCGGI21] that generalizes the notion of a Distributed
Point Function (DPF) [GI14]. Briefly, a DPF is used to distribute the
computation of a "point function", a function that evaluates to zero on every
input except at a programmable "point". The computation is distributed in such a
way that no one party knows either the point or what it evaluates to.

An IDPF generalizes this "point" to a path on a full binary tree from the root
to one of the leaves. It is evaluated on an "index" representing a unique node
of the tree. If the node is on the path, then function evaluates to to a
non-zero value; otherwise it evaluates to zero. This structure allows an IDPF to
provide the functionality required for the above protocol, while at the same
time ensuring the same degree of privacy as a DPF.

Our VDAF composes an IDPF with the "secure sketching" protocol of [BBCGGI21].
This protocol ensures that evaluating a set of input shares on a unique set of
candidate prefixes results in shares of a "one-hot" vector, i.e., a vector that
is zero everywhere except for one element, which is equal to one.

The name `poplar1` is an anagram of "hist", which is short for "histogram". It is a
nod toward the "subset histogram" problem formulated by [BBCGGI21] and for which
the `poplar1` is a solution.

## Incremental Distributed Point Functions (IDPFs)

> NOTE An implementation of IDPFs can be found
> [here](https://github.com/google/distributed_point_functions/).

An IDPF is defined over a domain of size `2^BITS`, where `BITS` is constant
defined by the IDPF. The Client specifies an index `alpha` and values `beta`,
one for each "level" `1 <= l <= BITS`. The key generation generates two IDPF
keys, one for each Aggregator. When evaluated at index `0 <= x < 2^l`, each
IDPF share returns an additive share of `beta[l]` if `x` is the `l`-bit prefix
of `alpha` and shares of zero otherwise.

> CP What does it mean for `x` to be the `l`-bit prefix of `alpha`? We need to
> be a bit more precise here.

> CP Why isn't the domain size actually `2^(BITS+1)`, i.e., the number of nodes
> in a binary tree of height `BITS` (excluding the root)?

Each `beta[l]` is a pair of elements of a finite field. Each level MAY have
different field parameters. Thus a concrete IDPF specifies associated types
`Field[1]`, `Field[2]`, ..., and `Field[BITS]` defining, respectively, the field
parameters at level 1, level 2, ..., and level `BITS`.

An IDPF is comprised of the following algorithms (let type `Value[l]` denote
`(Field[l], Field[l])` for each level `l`):

* `idpf_gen(alpha: Unsigned, beta: (Value[1], ..., Value[BITS])) -> key:
  (IDPFKey, IDPFKey)` is the randomized key-generation algorithm run by the
  client. Its inputs are the index `alpha` and the values `beta`. The value of
  `alpha` MUST be in range `[0, 2^BITS)`.

* `IDPFKey.eval(l: Unsigned, x: Unsigned) -> value: Value[l])` is deterministic,
  stateless key-evaluation algorithm run by each Aggregator. It returns the
  value corresponding to index `x`. The value of `l` MUST be in `[1, BITS]` and
  the value of `x` MUST be in range `[2^(l-1), 2^l)`.

A concrete IDPF specifies a single associated constant:

* `BITS: Unsigned` is the length of each Client input.

A concrete IDPF also specifies the following associated types:

* `Field[l]` for each level `1 <= l <= BITS`. Each defines the same methods and
  associated constants as `Field` in {{prio3}}.

Note that IDPF construction of [BBCGGI21] uses one field for the inner nodes of
the tree and a different, larger field for the leaf nodes. See [BBCGGI21],
Section 4.3.

Finally, an implementation note. The interface for IDPFs specified here is
stateless, in the sense that there is no state carried between IDPF evaluations.
This is to align the IDPF syntax with the VDAF abstraction boundary, which does
not include shared state across across VDAF evaluations. In practice, of course,
it will often be beneficial to expose a stateful API for IDPFs and carry the
state across evaluations.

## Construction {#poplar1-construction}

The VDAF involves two rounds of communication (`ROUNDS == 2`) and is defined for
two Aggregators (`SHARES == 2`).

### Setup

The verification parameter is a symmetric key shared by both Aggregators. This
VDAF has no public parameter.

~~~
def vdaf_setup():
  k_verify_init = gen_rand(SEED_SIZE)
  return (None, [(0, k_verify_init), (1, k_verify_init)])
~~~
{: #poplar1-eval-setup title="The setup algorithm for poplar1."}

#### Client

The client's input is an IDPF index, denoted `alpha`. The values are pairs of
field elements `(1, k)` where each `k` is chosen at random. This random value is
used as part of the secure sketching protocol of [BBCGGI21]. After evaluating
their IDPF key shares on the set of candidate prefixes, the sketching protocol
is used by the Aggregators to verify that they hold shares of a one-hot vector.
In addition, for each level of the tree, the prover generates random elements
`a`, `b`, and `c` and computes

~~~
    A = -2*a + k
    B = a*a + b - k*a + c
~~~

and sends additive shares of `a`, `b`, `c`, `A` and `B` to the Aggregators.
Putting everything together, the input-distribution algorithm is defined as
follows. Function `encode_input_share` is defined in {{poplar1-helper-functions}}.

~~~
def measurement_to_input_shares(_, alpha):
  if alpha < 2**BITS: raise ERR_INVALID_INPUT

  # Prepare IDPF values.
  beta = []
  correlation_shares_0, correlation_shares_1 = [], []
  for l in range(1,BITS+1):
    (k, a, b, c) = Field[l].rand_vec(4)

    # Construct values of the form (1, k), where k
    # is a random field element.
    beta += [(1, k)]

    # Create secret shares of correlations to aid
    # the Aggregators' computation.
    A = -2*a+k
    B = a*a + b - a * k + c
    correlation_share = Field[l].rand_vec(5)
    correlation_shares_1.append(correlation_share)
    correlation_shares_0.append(
      [a, b, c, A, B] - correlation_share)

  # Generate IDPF shares.
  (key_0, key_1) = idpf_gen(input, beta)

  input_shares = [
    encode_input_share(key_0, correlation_shares_0),
    encode_input_share(key_1, correlation_shares_1),
  ]

  return input_shares
~~~
{: #poplar1-mes2inp title="The input-distribution algorithm for poplar1."}

> TODO It would be more efficient to represent the correlation shares using PRG
> seeds as suggested in [BBCGGI21].

### Preparation

The aggregation parameter encodes a sequence of candidate prefixes. When an
Aggregator receives an input share from the Client, it begins by evaluating its
IDPF share on each candidate prefix, recovering a pair of vectors of field
elements `data_share` and `auth_share`, The Aggregators use `auth_share` and the
correlation shares provided by the Client to verify that their `data_share`
vectors are additive shares of a one-hot vector.

> CP Consider adding aggregation parameter as input to `k_verify_rand`
> derivation.

~~~
class PrepState:
  def __init__(verify_param, agg_param, nonce, input_share):
    (self.l, self.candidate_prefixes) = decode_indexes(agg_param)
    (self.idpf_key,
     self.correlation_shares) = decode_input_share(input_share)
    (self.party_id, k_verify_init) = verify_param
    self.k_verify_rand = get_key(k_verify_init, nonce)
    self.step = "ready"

  def next(self, inbound: Optional[Bytes]):
    l = self.l
    (a_share, b_share, c_share,
     A_share, B_share) = correlation_shares[l-1]

    if self.step == "ready" and inbound == None:
      # Evaluate IDPF on candidate prefixes.
      data_share, auth_share = [], []
      for x in self.candiate_prefixes:
        value = kdpf_key.eval(l, x)
        data_share.append(value[0])
        auth_share.append(value[1])

      # Prepare first sketch verification message.
      r = expand(Field[l], self.k_verify_rand, len(data_share))
      verifier_share_1 = [
         a_share + inner_product(data_share, r),
         b_share + inner_product(data_share, r * r),
         c_share + inner_product(auth_share, r),
      ]

      self.output_share = data_share
      self.step = "sketch round 1"
      return verifier_share_1

    elif self.step == "sketch round 1" and inbound != None:
      verifier_1 = Field[l].decode_vec(inbound)
      verifier_share_2 = [
        (verifier_1[0] * verifier_1[0] \
         - verifier_1[1] \
         - verifier_1[2]) * self.party_id \
        + A_share * verifer_1[0] \
        + B_share
      ]

      self.step = "sketch round 2"
      return Field[l].encode_vec(verifier_share_2)

    elif self.step == "sketch round 2" and inbound != None:
      verifier_2 = Field[l].decode_vec(inbound)
      if verifier_2 != 0: raise ERR_INVALID
      return Field[l].encode_vec(self.output_share)

    else: raise ERR_INVALID_STATE

def prep_shares_to_prep(agg_param, inbound: Vec[Bytes]):
  if len(inbound) != 2:
    raise ERR_INVALID_INPUT

  (l, _) = decode_indexes(agg_param)
  verifier = Field[l].decode_vec(inbound[0]) + \
             Field[l].decode_vec(inbound[1])

  return Field[l].encode_vec(verifier)
~~~
{: #poplar1-prep-state title="Preparation state for poplar1."}

### Aggregation

~~~
def out_shares_to_agg_share(agg_param, output_shares: Vec[Bytes]):
  (l, candidate_prefixes) = decode_indexes(agg_param)
  if len(output_shares) != len(candidate_prefixes):
    raise ERR_INVALID_INPUT

  agg_share = Field[l].zeros(len(candidate_prefixes))
  for output_share in output_shares:
    agg_share += Field[l].decode_vec(output_share)

  return Field[l].encode_vec(agg_share)
~~~
{: #poplar1-out2agg title="Aggregation algorithm for poplar1."}

### Unsharding

~~~
def agg_shares_to_result(agg_param, agg_shares: Vec[Bytes]):
  (l, _) = decode_indexes(agg_param)
  if len(agg_shares) != 2:
    raise ERR_INVALID_INPUT

  agg = Field[l].decode_vec(agg_shares[0]) + \
        Field[l].decode_vec(agg_shares[1]J)

  return Field[l].encode_vec(agg)
~~~
{: #poplar1-agg-output title="Computation of the aggregate result for poplar1."}

### Helper Functions {#poplar1-helper-functions}

> TODO Specify the following functionalities:

* `encode_input_share` is used to encode an input share, consisting of an IDPF
  key share and correlation shares.

* `decode_input_share` is used to decode an input share.

* `decode_indexes(encoded: Bytes) -> (l: Unsigned, indexes: Vec[Unsigned])`
  decodes a sequence of indexes, i.e., candidate indexes for IDFP evaluation.
  The value of `l` MUST be in range `[1, BITS]` and `indexes[i]` MUST be in range
  `[2^(l-1), 2^l)` for all `i`. An error is raised if `encoded` cannot be
  decoded.

# Security Considerations {#security}

> NOTE: This is a brief outline of the security considerations.  This section
> will be filled out more as the draft matures and security analyses are
> completed.

Multi-party protocols for privacy-preserving measurement have two essential
security gaols:

1. Privacy: An attacker that controls the network, the Collector, and a subset
   of Clients and Aggregators learns nothing about the measurements of honest
   Clients beyond what it can deduce from the aggregate result.

1. Robustness: An attacker that controls the network and a subset of Clients
   cannot cause the Collector to compute anything other than the aggregate of
   the measurements of honest Clients.

Note that it is also possible to consider a stronger form of robustness, where
the attacker also controls a subset of Aggregators (see [BBCGGI19], Section
6.3). In that case, it is important to ensure that the verifier randomness
shared between aggregators (`verify_params`, see [Setup](#setup)) is never
revealed to Clients. To satisfy this stronger notion of robustness, it is
RECOMMENDED that the Aggregators generate `verify_params` only after a set of
Client inputs has been collected for verification, and re-generate them for
each such set of inputs.

A VDAF is the core cryptographic primitive of a protocol that achieves
the above privacy and robustness goals. It is not sufficient on its own,
however.  The application will need to assure a few security properties,
for example:

* Securely distributing the long-lived parameters.
* Establishing secure channels:
  * Confidential and authentic channels among Aggregators, and between the
    Aggregators and the Collector; and
  * Confidential and Aggregator-authenticated channels between Clients and
    Aggregators.
* Enforcing the non-collusion properties required of the specific VDAF in use.

In such an environment, a VDAF provides the high-level privacy property
described above: The collector learns only the aggregate measurement, and
nothing about individual measurements aside from what can be inferred from the
aggregate result.  The aggregators learn neither individual measurements nor the
aggregate result.  The collector is assured that the aggregate statistic
accurately reflects the inputs as long as the Aggregators correctly executed
their role in the VDAF.

On their own, VDAFs do not mitigate Sybil attacks [Dou02]. In this attack, the
adversary observes a subset of input shares transmitted by a Client it is
interested in. It allows the input shares to be processed, but corrupts and
picks bogus inputs for the remaining Clients.  Applications can guard against
these risks by adding additional controls on measurement submission, such as
client authentication and rate limits.

VDAFs do not inherently provide differential privacy [Dwo06].  The VDAF approach
to private measurement can be viewed as complementary to differential privacy,
relying on non-collusion instead of statistical noise to protect the privacy of
the inputs.  It is possible that a future VDAF could incorporate differential
privacy features, e.g., by injecting noise before the sharding stage and
removing it after unsharding.

# IANA Considerations

This document makes no request of IANA.


--- back

# Acknowledgments
{:numbered="false"}

Thanks to Henry Corrigan-Gibbs, Mariana Raykova, and Christopher Wood for useful
feedback on the syntax of VDAF schemes.


