---
title: "Verifiable Distributed Aggregation Functions"
abbrev: "VDAF"
docname: draft-irtf-cfrg-vdaf-latest
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
    name: Richard L. Barnes
    organization: Cisco
    email: rlb@ipv.sx
 -
    name: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com
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

  #Vad16:
  #  title: "The Complexity of Differential Privacy"
  #  author:
  #    - ins: S. Vadhan
  #  date: 2016
  #  target: https://link.springer.com/chapter/10.1007/978-3-319-57048-8_7

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
privacy (DP)" {{Dwo06}}. Roughly speaking, a data aggregation system that is
differentially private ensures that the degree to which any individual
measurement influences the value of the aggregate result can be precisely
controlled. For example, in systems like RAPPOR {{EPK14}}, each user samples
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
overcome.  The Prio system {{CGB17}} (essentially a VDAF) has been deployed in
systems supporting hundreds of millions of users: The Mozilla Origin Telemetry
project {{OriginTelemetry}} and the Exposure Notification Private Analytics
collaboration among the Internet Security Research Group (ISRG), Google, Apple,
and others {{ENPA}}.

The VDAF abstraction laid out in {{vdaf}} represents a class of multi-party
protocols for privacy-preserving measurement proposed in the literature. These
protocols vary in their operational and security considerations, sometimes in
subtle but consequential ways. This document therefore has two important goals:

 1. Providing higher-level protocols like {{?DAP=I-D.draft-ietf-ppm-dap}} with a
    simple, uniform interface for accessing privacy-preserving measurement
    schemes, and documenting relevant operational and security bounds for that
    interface:

    1. General patterns of communications among the various actors involved in
       the system (clients, aggregation servers, and the collector of the
       aggregate result);
    1. Capabilities of a malicious coalition of servers attempting to divulge
       information about client measurements; and
    1. Conditions that are necessary to ensure that malicious clients cannot
       corrupt the computation.

 1. Providing cryptographers with design criteria that provide a clear
    deployment roadmap for new constructions.

This document also specifies two concrete VDAF schemes, each based on a protocol
from the literature.

* The aforementioned Prio system {{CGB17}} allows for the privacy-preserving
  computation of a variety aggregate statistics. The basic idea underlying Prio
  is fairly simple:
  1. Each client shards its measurement into a sequence of additive shares and
     distributes the shares among the aggregation servers.
  1. Next, each server adds up its shares locally, resulting in an additive
     share of the aggregate.
  1. Finally, the aggregation servers send their aggregate shares to the data
     collector, who combines them to obtain the aggregate result.

  The difficult part of this system is ensuring that the servers hold shares of
  a valid input, e.g., the input is an integer in a specific range. Thus Prio
  specifies a multi-party protocol for accomplishing this task.

  In {{prio3}} we describe Prio3, a VDAF that follows the same overall framework
  as the original Prio protocol, but incorporates techniques introduced in
  {{BBCGGI19}} that result in significant performance gains.

* More recently, Boneh et al. {{BBCGGI21}} described a protocol called Poplar
  for solving the `t`-heavy-hitters problem in a privacy-preserving manner. Here
  each client holds a bit-string of length `n`, and the goal of the aggregation
  servers is to compute the set of inputs that occur at least `t` times. The
  core primitive used in their protocol is a specialized Distributed Point
  Function (DPF) {{GI14}} that allows the servers to "query" their DPF shares on
  any bit-string of length shorter than or equal to `n`. As a result of this
  query, each of the servers has an additive share of a bit indicating whether
  the string is a prefix of the client's input. The protocol also specifies a
  multi-party computation for verifying that at most one string among a set of
  candidates is a prefix of the client's input.

  In {{poplar1}} we describe a VDAF called Poplar1 that implements this
  functionality.

Finally, perhaps the most complex aspect of schemes like Prio3 and Poplar1 is
the process by which the client-generated measurements are prepared for
aggregation. Because these constructions are based on secret sharing, the
servers will be required to exchange some amount of information in order to
verify the measurement is valid and can be aggregated. Depending on the
construction, this process may require multiple round trips over the network.

There are applications in which this verification step may not be necessary,
e.g., when the client's software is run a trusted execution environment. To
support these applications, this document also defines Distributed Aggregation
Functions (DAFs) as a simpler class of protocols that aim to provide the same
privacy guarantee as VDAFs but fall short of being verifiable.

> OPEN ISSUE Decide if we should give one or two example DAFs. There are natural
> variants of Prio3 and Poplar1 that might be worth describing.

The remainder of this document is organized as follows: {{overview}} gives a
brief overview of DAFs and VDAFs; {{daf}} defines the syntax for DAFs; {{vdaf}}
defines the syntax for VDAFs; {{prelim}} defines various functionalities that
are common to our constructions; {{prio3}} describes the Prio3 construction;
{{poplar1}} describes the Poplar1 construction; and {{security}} enumerates the
security considerations for VDAFs.

## Change Log

(*) Indicates a change that breaks wire compatibility with the previous draft.

02:

* Complete the initial specification of Poplar1.

* Extend (V)DAF syntax to include a "public share" output by the Client and
  distributed to all of the Aggregators. This is to accommodate "extractable"
  IDPFs as required for Poplar1. (See {{BBCGGI21}}, Section 4.3 for details.)

* Extend (V)DAF syntax to allow the unsharding step to take into account the
  number of measurements aggregated.

* Extend FLP syntax by adding a method for decoding the aggregate result from a
  vector of field elements. The new method takes into account the number of
  measurements.

* Prio3: Align aggregate result computation with updated FLP syntax.

* Prg: Add a method for statefully generating a vector of field elements.

* Field: Require that field elements are fully reduced before decoding. (*)

* Define new field Field255.

01:

* Require that VDAFs specify serialization of aggregate shares.

* Define Distributed Aggregation Functions (DAFs).

* Prio3: Move proof verifier check from `prep_next()` to
  `prep_shares_to_prep()`. (*)

* Remove public parameter and replace verification parameter with a
  "verification key" and "Aggregator ID".

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Algorithms in this document are written in Python 3. Type hints are used to
define input and output types. A fatal error in a program (e.g., failure to
parse one of the function parameters) is usually handled by raising an
exception.

A variable with type `Bytes` is a byte string. This document defines several
byte-string constants. When comprised of printable ASCII characters, they are
written as Python 3 byte-string literals (e.g., `b'some constant string'`).

A global constant `VERSION` is defined, which algorithms are free to use as
desired. Its value SHALL be `b'vdaf-02'`.

This document describes algorithms for multi-party computations in which the
parties typically communicate over a network. Wherever a quantity is defined
that must be be transmitted from one party to another, this document prescribes
a particular encoding of that quantity as a byte string.

> OPEN ISSUE It might be better to not be prescriptive about how quantities are
> encoded on the wire. See issue #58.

Some common functionalities:

* `zeros(len: Unsigned) -> Bytes` returns an array of zero bytes. The length of
  `output` MUST be `len`.

* `gen_rand(len: Unsigned) -> Bytes` returns an array of random bytes. The
  length of `output` MUST be `len`.

* `byte(int: Unsigned) -> Bytes` returns the representation of `int` as a byte
  string. The value of `int` MUST be in `[0,256)`.

* `xor(left: Bytes, right: Bytes) -> Bytes` returns the bitwise XOR of `left`
  and `right`. An exception is raised if the inputs are not the same length.

* `I2OSP` and `OS2IP` from {{!RFC8017}}, which are used, respectively, to
  convert a non-negative integer to a byte string and convert a byte string to a
  non-negative integer.

* `next_power_of_2(n: Unsigned) -> Unsigned` returns the smallest integer
  greater than or equal to `n` that is also a power of two.

# Overview

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
{: #overall-flow title="Overall data flow of a (V)DAF"}

In a DAF- or VDAF-based private measurement system, we distinguish three types
of actors: Clients, Aggregators, and Collectors.  The overall flow of the
measurement process is as follows:

* To submit an individual measurement, the Client shards the measurement into
  "input shares" and sends one input share to each Aggregator.
* The Aggregators convert their input shares into "output shares".
    * Output shares are in one-to-one correspondence with the input shares.
    * Just as each Aggregator receives one input share of each input, at the end
      of this process, each aggregator holds one output share.
    * In VDAFs, Aggregators will need to exchange information among themselves
      as part of the validation process.
* Each Aggregator combines the output shares across inputs in the batch to
  compute the "aggregate share" for that batch, i.e., its share of the desired
  aggregate result.
* The Aggregators submit their aggregate shares to the Collector, who combines
  them to obtain the aggregate result over the batch.

Aggregators are a new class of actor relative to traditional measurement systems
where clients submit measurements to a single server.  They are critical for
both the privacy properties of the system and, in the case of VDAFs, the
correctness of the measurements obtained.  The privacy properties of the system
are assured by non-collusion among Aggregators, and Aggregators are the entities
that perform validation of Client measurements.  Thus clients trust Aggregators
not to collude (typically it is required that at least one Aggregator is
honest), and Collectors trust Aggregators to correctly run the protocol.

Within the bounds of the non-collusion requirements of a given (V)DAF instance,
it is possible for the same entity to play more than one role.  For example, the
Collector could also act as an Aggregator, effectively using the other
Aggregator(s) to augment a basic client-server protocol.

In this document, we describe the computations performed by the actors in this
system. It is up to the higher-level protocol making use of the (V)DAF to
arrange for the required information to be delivered to the proper actors in the
proper sequence. In general, we assume that all communications are confidential
and mutually authenticated, with the exception that Clients submitting
measurements may be anonymous.

# Definition of DAFs {#daf}

By way of a gentle introduction to VDAFs, this section describes a simpler class
of schemes called Distributed Aggregation Functions (DAFs). Unlike VDAFs, DAFs
do not provide verifiability of the computation. Clients must therefore be
trusted to compute their input shares correctly. Because of this fact, the use
of a DAF is NOT RECOMMENDED for most applications. See {{security}} for
additional discussion.

A DAF scheme is used to compute a particular "aggregation function" over a set
of measurements generated by Clients. Depending on the aggregation function, the
Collector might select an "aggregation parameter" and disseminates it to the
Aggregators. The semantics of this parameter is specific to the aggregation
function, but in general it is used to represent the set of "queries" that can
be made on the measurement set. For example, the aggregation parameter is used
to represent the candidate prefixes in Poplar1 {{poplar1}}.

Execution of a DAF has four distinct stages:

* Sharding - Each Client generates input shares from its measurement and
  distributes them among the Aggregators.
* Preparation - Each Aggregator converts each input share into an output share
  compatible with the aggregation function. This computation involves the
  aggregation parameter. In general, each aggregation parameter may result in a
  different an output share.
* Aggregation - Each Aggregator combines a sequence of output shares into its
  aggregate share and sends the aggregate share to the Collector.
* Unsharding - The Collector combines the aggregate shares into the aggregate
  result.

Sharding and Preparation are done once per measurement. Aggregation and
Unsharding are done over a batch of measurements (more precisely, over the
recovered output shares).

A concrete DAF specifies an algorithm for the computation needed in each of
these stages. The interface of each algorithm is defined in the remainder of
this section. In addition, a concrete DAF defines the associated constants and
types enumerated in the following table.

| Parameter          | Description              |
|:-------------------|:-------------------------|
| `SHARES`      | Number of input shares into which each measurement is sharded |
| `Measurement` | Type of each measurement      |
| `AggParam`    | Type of aggregation parameter |
| `OutShare`    | Type of each output share     |
| `AggResult`   | Type of the aggregate result  |
{: #daf-param title="Constants and types defined by each concrete DAF."}

These types define some of the inputs and outputs of DAF methods at various
stages of the computation. Observe that only the measurements, output shares,
the aggregate result, and the aggregation parameter have an explicit type. All
other values --- in particular, the input shares and the aggregate shares ---
have type `Bytes` and are treated as opaque byte strings. This is because these
values must be transmitted between parties over a network.

> OPEN ISSUE It might be cleaner to define a type for each value, then have that
> type implement an encoding where necessary. This way each method parameter has
> a meaningful type hint. See issue#58.

## Sharding {#sec-daf-shard}

In order to protect the privacy of its measurements, a DAF Client shards its
measurements into a sequence of input shares. The `measurement_to_input_shares`
method is used for this purpose.

* `Daf.measurement_to_input_shares(input: Measurement) -> (Bytes, Vec[Bytes])`
  is the randomized input-distribution algorithm run by each Client. It consumes
  the measurement and produces a "public share", distributed to each of the
  Aggregators, and a corresponding sequence of input shares, one for each
  Aggregator. The length of the output vector MUST be `SHARES`.

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
{: #shard-flow title="The Client divides its measurement into input shares and
distributes them to the Aggregators."}

## Preparation {#sec-daf-prepare}

Once an Aggregator has received the public share and one of the input shares,
the next step is to prepare the input share for aggregation. This is
accomplished using the following algorithm:

* `Daf.prep(agg_id: Unsigned, agg_param: AggParam, public_share: Bytes,
  input_share: Bytes) -> OutShare` is the deterministic preparation algorithm.
  It takes as input the public share and one of the input shares generated by a
  Client, the Aggregator's unique identifier, and the aggregation parameter
  selected by the Collector and returns an output share.

The protocol in which the DAF is used MUST ensure that the Aggregator's
identifier is equal to the integer in range `[0, SHARES)` that matches the index
of `input_share` in the sequence of input shares output by the Client.

## Aggregation {#sec-daf-aggregate}

Once an Aggregator holds output shares for a batch of measurements (where
batches are defined by the application), it combines them into a share of the
desired aggregate result:

* `Daf.out_shares_to_agg_share(agg_param: AggParam, out_shares: Vec[OutShare])
  -> agg_share: Bytes` is the deterministic aggregation algorithm. It is run by
  each Aggregator a set of recovered output shares.

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
{: #aggregate-flow title="Aggregation of output shares. `B` indicates the number of
measurements in the batch."}

For simplicity, we have written this algorithm in a "one-shot" form, where all
output shares for a batch are provided at the same time. Many DAFs may also
support a "streaming" form, where shares are processed one at a time.

> OPEN ISSUE It may be worthwhile to explicitly define the "streaming" API. See
> issue#47.

## Unsharding {#sec-daf-unshard}

After the Aggregators have aggregated a sufficient number of output shares, each
sends its aggregate share to the Collector, who runs the following algorithm to
recover the following output:

* `Daf.agg_shares_to_result(agg_param: AggParam,
  agg_shares: Vec[Bytes], num_measurements: Unsigned) -> AggResult` is
  run by the Collector in order to compute the aggregate result from
  the Aggregators' shares. The length of `agg_shares` MUST be `SHARES`.
  `num_measurements` is the number of measurements that contributed to
  each of the aggregate shares. This algorithm is deterministic.

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
> privacy. (See the security considerations of {{?DAP=I-D.draft-ietf-ppm-dap}}.)
> Or is this out-of-scope of this document? See
> https://github.com/ietf-wg-ppm/ppm-specification/issues/19.

## Execution of a DAF {#daf-execution}

Securely executing a DAF involves emulating the following procedure.

<!--
Simon Friedberger: I think this would be easier to understand (also a bit
longer) if there was an Aggregator class which behaved like an actual aggregator
but with messages being sent by calling functions.
-->
~~~
def run_daf(Daf,
            agg_param: Daf.AggParam,
            measurements: Vec[Daf.Measurement]):
    out_shares = [ [] for j in range(Daf.SHARES) ]
    for measurement in measurements:
        # Each Client shards its measurement into input shares and
        # distributes them among the Aggregators.
        (public_share, input_shares) = \
            Daf.measurement_to_input_shares(measurement)

        # Each Aggregator prepares its input share for aggregation.
        for j in range(Daf.SHARES):
            out_shares[j].append(
                Daf.prep(j, agg_param, public_share, input_shares[j]))

    # Each Aggregator aggregates its output shares into an aggregate
    # share and sends it to the Collector.
    agg_shares = []
    for j in range(Daf.SHARES):
        agg_share_j = Daf.out_shares_to_agg_share(agg_param,
                                                  out_shares[j])
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate result.
    num_measurements = len(measurements)
    agg_result = Daf.agg_shares_to_result(agg_param, agg_shares,
                                          num_measurements)
    return agg_result
~~~
{: #run-daf title="Execution of a DAF."}

The inputs to this procedure are the same as the aggregation function computed by
the DAF: An aggregation parameter and a sequence of measurements. The procedure
prescribes how a DAF is executed in a "benign" environment in which there is no
adversary and the messages are passed among the protocol participants over
secure point-to-point channels. In reality, these channels need to be
instantiated by some "wrapper protocol", such as {{?DAP=I-D.draft-ietf-ppm-dap}},
that realizes these channels using suitable cryptographic mechanisms. Moreover,
some fraction of the Aggregators (or Clients) may be malicious and diverge from
their prescribed behaviors. {{security}} describes the execution of the DAF in
various adversarial environments and what properties the wrapper protocol needs
to provide in each.

# Definition of VDAFs {#vdaf}

Like DAFs described in the previous section, a VDAF scheme is used to compute a
particular aggregation function over a set of Client-generated measurements.
Evaluation of a VDAF involves the same four stages as for DAFs: Sharding,
Preparation, Aggregation, and Unsharding. However, the Preparation stage will
require interaction among the Aggregators in order to facilitate verifiability
of the computation's correctness. Accommodating this interaction will require
syntactic changes.

Overall execution of a VDAF comprises the following stages:

* Sharding - Computing input shares from an individual measurement
* Preparation - Conversion and verification of input shares to output shares
  compatible with the aggregation function being computed
* Aggregation - Combining a sequence of output shares into an aggregate share
* Unsharding - Combining a sequence of aggregate shares into an aggregate
  result

In contrast to DAFs, the Preparation stage for VDAFs now performs an additional
task: Verification of the validity of the recovered output shares. This process
ensures that aggregating the output shares will not lead to a garbled aggregate
result.

<!--
For some VDAFs, like Prio3 ({{prio3}}) or Poplar1 ({{poplar1}}), the output
shares are recovered first, then validated. For other protocols, like Prio+
[AGJOP21], there is no explicit verification step.
-->

The remainder of this section defines the VDAF interface. The attributes are
listed in {{vdaf-param}} are defined by each concrete VDAF.

| Parameter         | Description              |
|:------------------|:-------------------------|
| `VERIFY_KEY_SIZE` | Size (in bytes) of the verification key ({{sec-vdaf-prepare}}) |
| `ROUNDS`          | Number of rounds of communication during the Preparation stage ({{sec-vdaf-prepare}}) |
| `SHARES`          | Number of input shares into which each measurement is sharded ({{sec-vdaf-shard}}) |
| `Measurement`     | Type of each measurement |
| `AggParam`        | Type of aggregation parameter |
| `Prep`            | State of each Aggregator during Preparation ({{sec-vdaf-prepare}}) |
| `OutShare`        | Type of each output share |
| `AggResult`       | Type of the aggregate result |
{: #vdaf-param title="Constants and types defined by each concrete VDAF."}

Similarly to DAFs (see {[sec-daf}}), any output of a VDAF method that must be
transmitted from one party to another is treated as an opaque byte string. All
other quantities are given a concrete type.

> OPEN ISSUE It might be cleaner to define a type for each value, then have that
> type implement an encoding where necessary. See issue#58.

## Sharding {#sec-vdaf-shard}

Sharding is syntactically identical to DAFs (cf. {{sec-daf-shard}}):

* `Vdaf.measurement_to_input_shares(measurement: Measurement) -> (Bytes,
  Vec[Bytes])` is the randomized input-distribution algorithm run by each
  Client. It consumes the measurement and produces a public share, distributed
  to each of Aggregators, and the corresponding sequence of input shares, one
  for each Aggregator. Depending on the VDAF, the input shares may encode
  additional information used to verify the recovered output shares (e.g., the
  "proof shares" in Prio3 {{prio3}}). The length of the output vector MUST be
  `SHARES`.

## Preparation {#sec-vdaf-prepare}

To recover and verify output shares, the Aggregators interact with one another
over `ROUNDS` rounds. Prior to each round, each Aggregator constructs an
outbound message. Next, the sequence of outbound messages is combined into a
single message, called a "preparation message". (Each of the outbound messages
are called "preparation-message shares".) Finally, the preparation message is
distributed to the Aggregators to begin the next round.

An Aggregator begins the first round with its input share and it begins each
subsequent round with the previous preparation message. Its output in the last
round is its output share and its output in each of the preceding rounds is a
preparation-message share.

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

To facilitate the preparation process, a concrete VDAF implements the following
class methods:

* `Vdaf.prep_init(verify_key: Bytes, agg_id: Unsigned, agg_param: AggParam,
  nonce: Bytes, public_share: Bytes, input_share: Bytes) -> Prep` is the
  deterministic preparation-state initialization algorithm run by each
  Aggregator to begin processing its input share into an output share. Its
  inputs are the shared verification key (`verify_key`), the Aggregator's unique
  identifier (`agg_id`), the aggregation parameter (`agg_param`), the nonce
  provided by the environment (`nonce`, see {{run-vdaf}}), and the public share
  (`public_share`) and one of the input shares generated by the client
  (`input_share`). Its output is the Aggregator's initial preparation state.

  The length of `verify_key` MUST be `VERIFY_KEY_SIZE`. It is up to the high
  level protocol in which the VDAF is used to arrange for the distribution of
  the verification key among the Aggregators prior to the start of this phase of
  VDAF evaluation.

  > OPEN ISSUE What security properties do we need for this key exchange? See
  > issue#18.

  Protocols using the VDAF MUST ensure that the Aggregator's identifier is equal
  to the integer in range `[0, SHARES)` that matches the index of `input_share`
  in the sequence of input shares output by the Client. In addition, protocols
  MUST ensure that public share consumed by each of the Aggregators is
  identical. This is security critical for VDAFs such as Poplar1 that require an
  extractable distributed point function. (See {{poplar1}} for details.)

* `Vdaf.prep_next(prep: Prep, inbound: Optional[Bytes]) -> Union[Tuple[Prep,
  Bytes], OutShare]` is the deterministic preparation-state update algorithm run
  by each Aggregator. It updates the Aggregator's preparation state (`prep`) and
  returns either its next preparation state and its message share for the
  current round or, if this is the last round, its output share. An exception is
  raised if a valid output share could not be recovered. The input of this
  algorithm is the inbound preparation message or, if this is the first round,
  `None`.

* `Vdaf.prep_shares_to_prep(agg_param: AggParam, prep_shares: Vec[Bytes]) ->
  Bytes` is the deterministic preparation-message pre-processing algorithm. It
  combines the preparation-message shares generated by the Aggregators in the
  previous round into the preparation message consumed by each in the next
  round.

In effect, each Aggregator moves through a linear state machine with `ROUNDS+1`
states.  The Aggregator enters the first state on using the initialization
algorithm, and the update algorithm advances the Aggregator to the next state.
Thus, in addition to defining the number of rounds (`ROUNDS`), a VDAF instance
defines the state of the Aggregator after each round.

> TODO Consider how to bake this "linear state machine" condition into the
> syntax. Given that Python 3 is used as our pseudocode, it's easier to specify
> the preparation state using a class.

The preparation-state update accomplishes two tasks: recovery of output shares
from the input shares and ensuring that the recovered output shares are valid.
The abstraction boundary is drawn so that an Aggregator only recovers an output
share if it is deemed valid (at least, based on the Aggregator's view of the
protocol). Another way to draw this boundary would be to have the Aggregators
recover output shares first, then verify that they are valid. However, this
would allow the possibility of misusing the API by, say, aggregating an invalid
output share. Moreover, in protocols like Prio+ {{AGJOP21}} based on oblivious
transfer, it is necessary for the Aggregators to interact in order to recover
aggregatable output shares at all.

Note that it is possible for a VDAF to specify `ROUNDS == 0`, in which case each
Aggregator runs the preparation-state update algorithm once and immediately
recovers its output share without interacting with the other Aggregators.
However, most, if not all, constructions will require some amount of interaction
in order to ensure validity of the output shares (while also maintaining
privacy).

> OPEN ISSUE accommodating 0-round VDAFs may require syntax changes if, for
> example, public keys are required. On the other hand, we could consider
> defining this class of schemes as a different primitive. See issue#77.

## Aggregation {#sec-vdaf-aggregate}

VDAF Aggregation is identical to DAF Aggregation (cf. {{sec-daf-aggregate}}):

* `Vdaf.out_shares_to_agg_share(agg_param: AggParam, out_shares: Vec[OutShare])
  -> agg_share: Bytes` is the deterministic aggregation algorithm. It is run by
  each Aggregator over the output shares it has computed over a batch of
  measurement inputs.

The data flow for this stage is illustrated in {{aggregate-flow}}. Here again,
we have the aggregation algorithm in a "one-shot" form, where all shares for a
batch are provided at the same time. VDAFs typically also support a "streaming"
form, where shares are processed one at a time.

## Unsharding {#sec-vdaf-unshard}

VDAF Unsharding is identical to DAF Unsharding (cf. {{sec-daf-unshard}}):

* `Vdaf.agg_shares_to_result(agg_param: AggParam,
  agg_shares: Vec[Bytes], num_measurements: Unsigned) -> AggResult` is
  run by the Collector in order to compute the aggregate result from
  the Aggregators' shares. The length of `agg_shares` MUST be `SHARES`.
  `num_measurements` is the number of measurements that contributed to
  each of the aggregate shares. This algorithm is deterministic.

The data flow for this stage is illustrated in {{unshard-flow}}.

## Execution of a VDAF {#vdaf-execution}

Secure execution of a VDAF involves simulating the following procedure.

~~~
def run_vdaf(Vdaf,
             agg_param: Vdaf.AggParam,
             nonces: Vec[Bytes],
             measurements: Vec[Vdaf.Measurement]):
    # Generate the long-lived verification key.
    verify_key = gen_rand(Vdaf.VERIFY_KEY_SIZE)

    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        # Each Client shards its measurement into input shares.
        (public_share, input_shares) = \
            Vdaf.measurement_to_input_shares(measurement)

        # Each Aggregator initializes its preparation state.
        prep_states = []
        for j in range(Vdaf.SHARES):
            state = Vdaf.prep_init(verify_key, j,
                                   agg_param,
                                   nonce,
                                   public_share,
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
            # This is where we would send messages over the
            # network in a distributed VDAF computation.
            if i < Vdaf.ROUNDS:
                inbound = Vdaf.prep_shares_to_prep(agg_param,
                                                   outbound)

        # The final outputs of prepare phase are the output shares.
        out_shares.append(outbound)

    # Each Aggregator aggregates its output shares into an
    # aggregate share. In a distributed VDAF computation, the
    # aggregate shares are sent over the network.
    agg_shares = []
    for j in range(Vdaf.SHARES):
        out_shares_j = [out[j] for out in out_shares]
        agg_share_j = Vdaf.out_shares_to_agg_share(agg_param,
                                                   out_shares_j)
        agg_shares.append(agg_share_j)

    # Collector unshards the aggregate.
    num_measurements = len(measurements)
    agg_result = Vdaf.agg_shares_to_result(agg_param, agg_shares,
                                           num_measurements)
    return agg_result
~~~
{: #run-vdaf title="Execution of a VDAF."}

The inputs to this algorithm are the aggregation parameter, a list of
measurements, and a nonce for each measurement. This document does not specify
how the nonces are chosen, but security requires that the nonces be unique. See
{{security}} for details. As explained in {{daf-execution}}, the secure
execution of a VDAF requires the application to instantiate secure channels
between each of the protocol participants.

# Preliminaries {#prelim}

This section describes the primitives that are common to the VDAFs specified in
this document.

## Finite Fields {#field}

Both Prio3 and Poplar1 use finite fields of prime order. Finite field
elements are represented by a class `Field` with the following associated
parameters:

* `MODULUS: Unsigned` is the prime modulus that defines the field.

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

Likewise, each concrete `Field` implements a constructor for converting an
unsigned integer into a field element:

* `Field(integer: Unsigned)` returns `integer` represented as a field element.
  The value of `integer` MUST be less than `Field.MODULUS`.

Finally, each concrete `Field` has two derived class methods, one for encoding
a vector of field elements as a byte string and another for decoding a vector of
field elements.

~~~
def encode_vec(Field, data: Vec[Field]) -> Bytes:
    encoded = Bytes()
    for x in data:
        encoded += I2OSP(x.as_unsigned(), Field.ENCODED_SIZE)
    return encoded

def decode_vec(Field, encoded: Bytes) -> Vec[Field]:
    L = Field.ENCODED_SIZE
    if len(encoded) % L != 0:
        raise ERR_DECODE

    vec = []
    for i in range(0, len(encoded), L):
        encoded_x = encoded[i:i+L]
        x = OS2IP(encoded_x)
        if x >= Field.MODULUS:
            raise ERR_DECODE # Integer is larger than modulus
        vec.append(Field(x))
    return vec
~~~
{: #field-derived-methods title="Derived class methods for finite fields."}

### Auxiliary Functions

The following auxiliary functions on vectors of field elements are used in the
remainder of this document. Note that an exception is raised by each function if
the operands are not the same length.

~~~
# Compute the inner product of the operands.
def inner_product(left: Vec[Field], right: Vec[Field]) -> Field:
    return sum(map(lambda x: x[0] * x[1], zip(left, right)))

# Subtract the right operand from the left and return the result.
def vec_sub(left: Vec[Field], right: Vec[Field]):
    return list(map(lambda x: x[0] - x[1], zip(left, right)))

# Add the right operand to the left and return the result.
def vec_add(left: Vec[Field], right: Vec[Field]):
    return list(map(lambda x: x[0] + x[1], zip(left, right)))
~~~
{: #field-helper-functions title="Common functions for finite fields."}

### FFT-Friendly Fields {#field-fft-friendly}

Some VDAFs require fields that are suitable for efficient computation of the
discrete Fourier transform. (One example is Prio3 ({{prio3}}) when instantiated
with the generic FLP of {{flp-generic-construction}}.) Specifically, a field is
said to be "FFT-friendly" if, in addition to satisfying the interface described
in {{field}}, it implements the following method:

* `Field.gen() -> Field` returns the generator of a large subgroup of the
  multiplicative group.

FFT-friendly fields also define the following parameter:

* `GEN_ORDER: Unsigned` is the order of a multiplicative subgroup generated by
  `Field.gen()`. This value MUST be a power of 2.

### Parameters

The tables below define finite fields used in the remainder of this document.

| Parameter       | Value   |
|:----------------|:--------|
| MODULUS         | 2^32 * 4294967295 + 1 |
| ENCODED_SIZE    | 8 |
| Generator       | 7^4294967295 |
| GEN_ORDER       | 2^32 |
{: #field64 title="Field64, an FFT-friendly field."}

| Parameter       | Value   |
|:----------------|:--------|
| MODULUS         | 2^66 * 4611686018427387897 + 1 |
| ENCODED_SIZE    | 16 |
| Generator       | 7^4611686018427387897 |
| GEN_ORDER       | 2^66 |
{: #field128 title="Field128, an FFT-friendly field."}

| Parameter       | Value   |
|:----------------|:--------|
| MODULUS         | 2^255 - 19 |
| ENCODED_SIZE    | 32 |
{: #field255 title="Field255."}

> OPEN ISSUE We currently use big-endian for encoding field elements. However,
> for implementations of `GF(2^255-19)`, little endian is more common. See
> issue#90.

## Pseudorandom Generators {#prg}

A pseudorandom generator (PRG) is used to expand a short, (pseudo)random seed
into a long string of pseudorandom bits. A PRG suitable for this document
implements the interface specified in this section. Concrete constructions are
described in the subsections that follow.

PRGs are defined by a class `Prg` with the following associated parameter:

* `SEED_SIZE: Unsigned` is the size (in bytes) of a seed.

A concrete `Prg` implements the following class method:

* `Prg(seed: Bytes, info: Bytes)` constructs an instance of `Prg` from the given
  seed and info string. The seed MUST be of length `SEED_SIZE` and MUST be
  generated securely (i.e., it is either the output of `gen_rand` or a previous
  invocation of the PRG). The info string is used for domain separation.

* `prg.next(length: Unsigned)` returns the next `length` bytes of output of PRG.
  If the seed was securely generated, the output can be treated as pseudorandom.

Each `Prg` has two derived class methods. The first is used to derive a fresh
seed from an existing one. The second is used to compute a sequence of
pseudorandom field elements. For each method, the seed MUST be of length
`SEED_SIZE` and MUST be generated securely (i.e., it is either the output of
`gen_rand` or a previous invocation of the PRG).

~~~
# Derive a new seed.
def derive_seed(Prg, seed: Bytes, info: Bytes) -> bytes:
    prg = Prg(seed, info)
    return prg.next(Prg.SEED_SIZE)

# Output the next `length` pseudorandom elements of `Field`.
def next_vec(self, Field, length: Unsigned):
    m = next_power_of_2(Field.MODULUS) - 1
    vec = []
    while len(vec) < length:
        x = OS2IP(self.next(Field.ENCODED_SIZE))
        x &= m
        if x < Field.MODULUS:
            vec.append(Field(x))
    return vec

# Expand the input `seed` into vector of `length` field elements.
def expand_into_vec(Prg,
                    Field,
                    seed: Bytes,
                    info: Bytes,
                    length: Unsigned):
    prg = Prg(seed, info)
    return prg.next_vec(Field, length)
~~~
{: #prg-derived-methods title="Derived class methods for PRGs."}

### PrgAes128 {#prg-aes128}

> OPEN ISSUE Phillipp points out that a fixed-key mode of AES may be more
> performant (https://eprint.iacr.org/2019/074.pdf). See issue#32.

Our first construction, `PrgAes128`, converts a blockcipher, namely AES-128,
into a PRG. Seed expansion involves two steps. In the first step, CMAC
{{!RFC4493}} is applied to the seed and info string to get a fresh key. In the
second step, the fresh key is used in CTR-mode to produce a key stream for
generating the output. A fixed initialization vector (IV) is used.

~~~
class PrgAes128:

    SEED_SIZE: Unsigned = 16

    def __init__(self, seed, info):
        self.length_consumed = 0

        # Use CMAC as a pseudorandom function to derive a key.
        self.key = AES128-CMAC(seed, info)

    def next(self, length):
        self.length_consumed += length

        # CTR-mode encryption of the all-zero string of the desired
        # length and using a fixed, all-zero IV.
        stream = AES128-CTR(key, zeros(16), zeros(self.length_consumed))
        return stream[-length:]
~~~
{: title="Definition of PRG PrgAes128."}

# Prio3 {#prio3}

> NOTE This construction has not undergone significant security analysis.

This section describes Prio3, a VDAF for Prio {{CGB17}}. Prio is suitable for
a wide variety of aggregation functions, including (but not limited to) sum,
mean, standard deviation, estimation of quantiles (e.g., median), and linear
regression. In fact, the scheme described in this section is compatible with any
aggregation function that has the following structure:

* Each measurement is encoded as a vector over some finite field.
* Input validity is determined by an arithmetic circuit evaluated over the
  encoded input. (An "arithmetic circuit" is a function comprised of arithmetic
  operations in the field.) The circuit's output is a single field element: if
  zero, then the input is said to be "valid"; otherwise, if the output is
  non-zero, then the input is said to be "invalid".
* The aggregate result is obtained by summing up the encoded input vectors and
  computing some function of the sum.

At a high level, Prio3 distributes this computation as follows. Each Client
first shards its measurement by first encoding it, then splitting the vector into
secret shares and sending a share to each Aggregator. Next, in the preparation
phase, the Aggregators carry out a multi-party computation to determine if their
shares correspond to a valid input (as determined by the arithmetic circuit).
This computation involves a "proof" of validity generated by the Client. Next,
each Aggregator sums up its input shares locally. Finally, the Collector sums up
the aggregate shares and computes the aggregate result.

This VDAF does not have an aggregation parameter. Instead, the output share is
derived from the input share by applying a fixed map. See {{poplar1}} for an
example of a VDAF that makes meaningful use of the aggregation parameter.

As the name implies, Prio3 is a descendant of the original Prio construction.
A second iteration was deployed in the {{ENPA}} system, and like the VDAF
described here, the ENPA system was built from techniques introduced in
{{BBCGGI19}} that significantly improve communication cost. That system was
specialized for a particular aggregation function; the goal of Prio3 is to
provide the same level of generality as the original construction.

The core component of Prio3 is a "Fully Linear Proof (FLP)" system. Introduced
by {{BBCGGI19}}, the FLP encapsulates the functionality required for encoding
and validating inputs. Prio3 can be thought of as a transformation of a
particular class of FLPs into a VDAF.

The remainder of this section is structured as follows. The syntax for FLPs is
described in {{flp}}. The generic transformation of an FLP into Prio3 is
specified in {{prio3-construction}}. Next, a concrete FLP suitable for any
validity circuit is specified in {{flp-generic}}. Finally, instantiations of
Prio3 for various types of measurements are specified in
{{prio3-instantiations}}. Test vectors can be found in {{test-vectors}}.

## Fully Linear Proof (FLP) Systems {#flp}

Conceptually, an FLP is a two-party protocol executed by a prover and a
verifier. In actual use, however, the prover's computation is carried out by the
Client, and the verifier's computation is distributed among the Aggregators. The
Client generates a "proof" of its input's validity and distributes shares of the
proof to the Aggregators. Each Aggregator then performs some a computation on
its input share and proof share locally and sends the result to the other
Aggregators. Combining the exchanged messages allows each Aggregator to decide
if it holds a share of a valid input. (See {{prio3-construction}} for details.)

As usual, we will describe the interface implemented by a concrete FLP in terms
of an abstract base class `Flp` that specifies the set of methods and parameters
a concrete FLP must provide.

The parameters provided by a concrete FLP are listed in {{flp-param}}.

| Parameter        | Description               |
|:-----------------|:--------------------------|
| `PROVE_RAND_LEN` | Length of the prover randomness, the number of random field elements consumed by the prover when generating a proof |
| `QUERY_RAND_LEN` | Length of the query randomness, the number of random field elements consumed by the verifier |
| `JOINT_RAND_LEN` | Length of the joint randomness, the number of random field elements consumed by both the prover and verifier |
| `INPUT_LEN`      | Length of the encoded measurement ({{flp-encode}}) |
| `OUTPUT_LEN`     | Length of the aggregatable output ({{flp-encode}}) |
| `PROOF_LEN`      | Length of the proof       |
| `VERIFIER_LEN`   | Length of the verifier message generated by querying the input and proof |
| `Measurement`    | Type of the measurement   |
| `AggResult`      | Type of the aggregate result |
| `Field`          | As defined in ({{field}}) |
{: #flp-param title="Constants and types defined by a concrete FLP."}

An FLP specifies the following algorithms for generating and verifying proofs of
validity (encoding is described below in {{flp-encode}}):

* `Flp.prove(input: Vec[Field], prove_rand: Vec[Field], joint_rand: Vec[Field])
  -> Vec[Field]` is the deterministic proof-generation algorithm run by the
  prover. Its inputs are the encoded input, the "prover randomness"
  `prove_rand`, and the "joint randomness" `joint_rand`. The prover randomness is
  used only by the prover, but the joint randomness is shared by both the prover
  and verifier.

* `Flp.query(input: Vec[Field], proof: Vec[Field], query_rand: Vec[Field],
  joint_rand: Vec[Field], num_shares: Unsigned) -> Vec[Field]` is the
  query-generation algorithm run by the verifier. This is used to "query" the
  input and proof. The result of the query (i.e., the output of this function)
  is called the "verifier message". In addition to the input and proof, this
  algorithm takes as input the query randomness `query_rand` and the joint
  randomness `joint_rand`. The former is used only by the verifier. `num_shares`
  specifies how many input and proof shares were generated.

* `Flp.decide(verifier: Vec[Field]) -> Bool` is the deterministic decision
  algorithm run by the verifier. It takes as input the verifier message and
  outputs a boolean indicating if the input from which it was generated is
  valid.

Our application requires that the FLP is "fully linear" in the sense defined in
{{BBCGGI19}}. As a practical matter, what this property implies is that, when
run on a share of the input and proof, the query-generation algorithm outputs a
share of the verifier message. Furthermore, the "strong zero-knowledge" property
of the FLP system ensures that the verifier message reveals nothing about the
input's validity. Therefore, to decide if an input is valid, the Aggregators
will run the query-generation algorithm locally, exchange verifier shares,
combine them to recover the verifier message, and run the decision algorithm.

The query-generation algorithm includes a parameter `num_shares` that specifies
the number of shares of the input and proof that were generated. If these data
are not secret shared, then `num_shares == 1`. This parameter is useful for
certain FLP constructions. For example, the FLP in {{flp-generic}} is defined in
terms of an arithmetic circuit; when the circuit contains constants, it is
sometimes necessary to normalize those constants to ensure that the circuit's
output, when run on a valid input, is the same regardless of the number of
shares.

An FLP is executed by the prover and verifier as follows:

~~~
def run_flp(Flp, inp: Vec[Flp.Field], num_shares: Unsigned):
    joint_rand = Flp.Field.rand_vec(Flp.JOINT_RAND_LEN)
    prove_rand = Flp.Field.rand_vec(Flp.PROVE_RAND_LEN)
    query_rand = Flp.Field.rand_vec(Flp.QUERY_RAND_LEN)

    # Prover generates the proof.
    proof = Flp.prove(inp, prove_rand, joint_rand)

    # Verifier queries the input and proof.
    verifier = Flp.query(inp, proof, query_rand, joint_rand, num_shares)

    # Verifier decides if the input is valid.
    return Flp.decide(verifier)
~~~
{: #run-flp title="Execution of an FLP."}

The proof system is constructed so that, if `input` is a valid input, then
`run_flp(Flp, input, 1)` always returns `True`. On the other hand, if `input` is
invalid, then as long as `joint_rand` and `query_rand` are generated uniform
randomly, the output is `False` with overwhelming probability.

We remark that {{BBCGGI19}} defines a much larger class of fully linear proof
systems than we consider here. In particular, what is called an "FLP" here is
called a 1.5-round, public-coin, interactive oracle proof system in their paper.

### Encoding the Input {#flp-encode}

The type of measurement being aggregated is defined by the FLP. Hence, the FLP
also specifies a method of encoding raw measurements as a vector of field
elements:

* `Flp.encode(measurement: Measurement) -> Vec[Field]` encodes a raw measurement
  as a vector of field elements. The return value MUST be of length `INPUT_LEN`.

For some FLPs, the encoded input also includes redundant field elements that are
useful for checking the proof, but which are not needed after the proof has been
checked. An example is the "integer sum" data type from {{CGB17}} in which an
integer in range `[0, 2^k)` is encoded as a vector of `k` field elements (this
type is also defined in {{prio3-sum}}). After consuming this vector,
all that is needed is the integer it represents. Thus the FLP defines an
algorithm for truncating the input to the length of the aggregated output:

* `Flp.truncate(input: Vec[Field]) -> Vec[Field]` maps an encoded input to an
  aggregatable output. The length of the input MUST be `INPUT_LEN` and the length
  of the output MUST be `OUTPUT_LEN`.

Once the aggregate shares have been computed and combined together, their sum
can be converted into the aggregate result. This could be a projection from
the FLP's field to the integers, or it could include additional
post-processing.

* `Flp.decode(output: Vec[Field], num_measurements: Unsigned) -> AggResult`
  maps a sum of aggregate shares to an aggregate result. The length of the
  input MUST be `OUTPUT_LEN`. `num_measurements` is the number of measurements
  that contributed to the aggregated output.

We remark that, taken together, these three functionalities correspond roughly
to the notion of "Affine-aggregatable encodings (AFEs)" from {{CGB17}}.

## Construction {#prio3-construction}

This section specifies `Prio3`, an implementation of the `Vdaf` interface
({{vdaf}}). It has two generic parameters: an `Flp` ({{flp}}) and a `Prg`
({{prg}}). The associated constants and types required by the `Vdaf` interface
are defined in {{prio3-param}}. The methods required for sharding, preparation,
aggregation, and unsharding are described in the remaining subsections.

| Parameter         | Value             |
|:------------------|:------------------|
| `VERIFY_KEY_SIZE` | `Prg.SEED_SIZE`   |
| `ROUNDS`          | `1`               |
| `SHARES`          | in `[2, 255)`     |
| `Measurement`     | `Flp.Measurement` |
| `AggParam`        | `None`            |
| `Prep`            | `Tuple[Vec[Flp.Field], Optional[Bytes], Bytes]` |
| `OutShare`        | `Vec[Flp.Field]`  |
| `AggResult`       | `Flp.AggResult`   |
{: #prio3-param title="Associated parameters for the Prio3 VDAF."}

### Sharding

Recall from {{flp}} that the FLP syntax calls for "joint randomness" shared by
the prover (i.e., the Client) and the verifier (i.e., the Aggregators). VDAFs
have no such notion. Instead, the Client derives the joint randomness from its
input in a way that allows the Aggregators to reconstruct it from their input
shares. (This idea is based on the Fiat-Shamir heuristic and is described in
Section 6.2.3 of {{BBCGGI19}}.)

The input-distribution algorithm involves the following steps:

1. Encode the Client's raw measurement as an input for the FLP
1. Shard the input into a sequence of input shares
1. Derive the joint randomness from the input shares
1. Run the FLP proof-generation algorithm using the derived joint randomness
1. Shard the proof into a sequence of proof shares

The algorithm is specified below. Notice that only one set of input and proof
shares (called the "leader" shares below) are vectors of field elements. The
other shares (called the "helper" shares) are represented instead by PRG seeds,
which are expanded into vectors of field elements.

The code refers to a pair of auxiliary functions for encoding the shares. These
are called `encode_leader_share` and `encode_helper_share` respectively and they
are described in {{prio3-helper-functions}}.

~~~
def measurement_to_input_shares(Prio3, measurement):
    # Domain separation tag for PRG info string
    dst = VERSION + b' prio3'
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
            dst + byte(j+1),
            Prio3.Flp.INPUT_LEN
        )
        leader_input_share = vec_sub(leader_input_share,
                                     helper_input_share)
        encoded = Prio3.Flp.Field.encode_vec(helper_input_share)
        k_hint = Prio3.Prg.derive_seed(k_blind,
                                       byte(j+1) + encoded)
        k_joint_rand = xor(k_joint_rand, k_hint)
        k_helper_input_shares.append(k_share)
        k_helper_blinds.append(k_blind)
        k_helper_hints.append(k_hint)
    k_leader_blind = gen_rand(Prio3.Prg.SEED_SIZE)
    encoded = Prio3.Flp.Field.encode_vec(leader_input_share)
    k_leader_hint = Prio3.Prg.derive_seed(k_leader_blind,
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
        dst,
        Prio3.Flp.PROVE_RAND_LEN
    )
    joint_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        k_joint_rand,
        dst,
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
            dst + byte(j+1),
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
    return (b'', input_shares)
~~~
{: #prio3-eval-input title="Input-distribution algorithm for Prio3."}

### Preparation

This section describes the process of recovering output shares from the input
shares. The high-level idea is that each Aggregator first queries its input and
proof share locally, then exchanges its verifier share with the other
Aggregators. The verifier shares are then combined into the verifier message,
which is used to decide whether to accept.

In addition, the Aggregators must ensure that they have all used the same joint
randomness for the query-generation algorithm. The joint randomness is generated
by a PRG seed. Each Aggregator derives an XOR secret share of this seed from its
input share and the "blind" generated by the client. Thus, before running the
query-generation algorithm, it must first gather the XOR secret shares derived
by the other Aggregators.

In order to avoid extra round of communication, the Client sends each Aggregator
a "hint" equal to the XOR of the other Aggregators' shares of the joint
randomness seed. This leaves open the possibility that the Client cheated by,
say, forcing the Aggregators to use joint randomness that biases the proof check
procedure some way in its favor. To mitigate this, the Aggregators also check
that they have all computed the same joint randomness seed before accepting
their output shares. To do so, they exchange their XOR shares of the PRG seed
along with their verifier shares.

> NOTE This optimization somewhat diverges from Section 6.2.3 of {{BBCGGI19}}.
> Security analysis is needed.

The algorithms required for preparation are defined as follows. These algorithms
make use of encoding and decoding methods defined in {{prio3-helper-functions}}.

~~~
def prep_init(Prio3, verify_key, agg_id, _agg_param,
              nonce, _public_share, input_share):
    # Domain separation tag for PRG info string
    dst = VERSION + b' prio3'

    (input_share, proof_share, k_blind, k_hint) = \
        Prio3.decode_leader_share(input_share) if agg_id == 0 else \
        Prio3.decode_helper_share(dst, agg_id, input_share)

    out_share = Prio3.Flp.truncate(input_share)

    k_query_rand = Prio3.Prg.derive_seed(verify_key, byte(255) + nonce)
    query_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        k_query_rand,
        dst,
        Prio3.Flp.QUERY_RAND_LEN
    )
    joint_rand, k_joint_rand, k_joint_rand_share = [], None, None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded = Prio3.Flp.Field.encode_vec(input_share)
        k_joint_rand_share = Prio3.Prg.derive_seed(
            k_blind, byte(agg_id) + encoded)
        k_joint_rand = xor(k_hint, k_joint_rand_share)
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_joint_rand,
            dst,
            Prio3.Flp.JOINT_RAND_LEN
        )
    verifier_share = Prio3.Flp.query(input_share,
                                     proof_share,
                                     query_rand,
                                     joint_rand,
                                     Prio3.SHARES)

    prep_msg = Prio3.encode_prep_share(verifier_share,
                                       k_joint_rand_share)
    return (out_share, k_joint_rand, prep_msg)

def prep_next(Prio3, prep, inbound):
    (out_share, k_joint_rand, prep_msg) = prep

    if inbound is None:
        return (prep, prep_msg)

    k_joint_rand_check = Prio3.decode_prep_msg(inbound)
    if k_joint_rand_check != k_joint_rand:
        raise ERR_VERIFY # joint randomness check failed

    return out_share

def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
    verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
    k_joint_rand_check = zeros(Prio3.Prg.SEED_SIZE)
    for encoded in prep_shares:
        (verifier_share, k_joint_rand_share) = \
            Prio3.decode_prep_share(encoded)

        verifier = vec_add(verifier, verifier_share)

        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_joint_rand_check = xor(k_joint_rand_check,
                                     k_joint_rand_share)

    if not Prio3.Flp.decide(verifier):
        raise ERR_VERIFY # proof verifier check failed

    return Prio3.encode_prep_msg(k_joint_rand_check)
~~~
{: #prio3-prep-state title="Preparation state for Prio3."}

### Aggregation

Aggregating a set of output shares is simply a matter of adding up the vectors
element-wise.

~~~
def out_shares_to_agg_share(Prio3, _agg_param, out_shares):
    agg_share = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
    for out_share in out_shares:
        agg_share = vec_add(agg_share, out_share)
    return Prio3.Flp.Field.encode_vec(agg_share)
~~~
{: #prio3-out2agg title="Aggregation algorithm for Prio3."}

### Unsharding

To unshard a set of aggregate shares, the Collector first adds up the vectors
element-wise. It then converts each element of the vector into an integer.

~~~
def agg_shares_to_result(Prio3, _agg_param, agg_shares,
                         num_measurements):
    agg = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
    for agg_share in agg_shares:
        agg = vec_add(agg, Prio3.Flp.Field.decode_vec(agg_share))
    return Prio3.Flp.decode(agg, num_measurements)
~~~
{: #prio3-agg-output title="Computation of the aggregate result for Prio3."}

### Auxiliary Functions {#prio3-helper-functions}

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

def decode_helper_share(Prio3, dst, agg_id, encoded):
    l = Prio3.Prg.SEED_SIZE
    k_input_share, encoded = encoded[:l], encoded[l:]
    input_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                            k_input_share,
                                            dst + byte(agg_id),
                                            Prio3.Flp.INPUT_LEN)
    k_proof_share, encoded = encoded[:l], encoded[l:]
    proof_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                            k_proof_share,
                                            dst + byte(agg_id),
                                            Prio3.Flp.PROOF_LEN)
    k_blind, k_hint = None, None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        k_blind, encoded = encoded[:l], encoded[l:]
        k_hint, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return (input_share, proof_share, k_blind, k_hint)

def encode_prep_share(Prio3, verifier, k_joint_rand):
    encoded = Bytes()
    encoded += Prio3.Flp.Field.encode_vec(verifier)
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_joint_rand
    return encoded

def decode_prep_share(Prio3, encoded):
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

def encode_prep_msg(Prio3, k_joint_rand_check):
    encoded = Bytes()
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_joint_rand_check
    return encoded

def decode_prep_msg(Prio3, encoded):
    k_joint_rand_check = None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        l = Prio3.Prg.SEED_SIZE
        k_joint_rand_check, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return k_joint_rand_check
~~~
{: #prio3-helpers title="Helper functions required for Prio3."}

## A General-Purpose FLP {#flp-generic}

This section describes an FLP based on the construction from in {{BBCGGI19}},
Section 4.2. We begin in {{flp-generic-overview}} with an overview of their proof
system and the extensions to their proof system made here. The construction is
specified in {{flp-generic-construction}}.

> OPEN ISSUE We're not yet sure if specifying this general-purpose FLP is
> desirable. It might be preferable to specify specialized FLPs for each data
> type that we want to standardize, for two reasons. First, clear and concise
> specifications are likely easier to write for specialized FLPs rather than the
> general one. Second, we may end up tailoring each FLP to the measurement type
> in a way that improves performance, but breaks compatibility with the
> general-purpose FLP.
>
> In any case, we can't make this decision until we know which data types to
> standardize, so for now, we'll stick with the general-purpose construction.
> The reference implementation can be found at
> https://github.com/cfrg/draft-irtf-cfrg-vdaf/tree/main/poc.

> OPEN ISSUE Chris Wood points out that the this section reads more like a paper
> than a standard. Eventually we'll want to work this into something that is
> readily consumable by the CFRG.

### Overview {#flp-generic-overview}

In the proof system of {{BBCGGI19}}, validity is defined via an arithmetic
circuit evaluated over the input: If the circuit output is zero, then the input
is deemed valid; otherwise, if the circuit output is non-zero, then the input is
deemed invalid. Thus the goal of the proof system is merely to allow the
verifier to evaluate the validity circuit over the input. For our application
({{prio3}}), this computation is distributed among multiple Aggregators, each of
which has only a share of the input.

Suppose for a moment that the validity circuit `C` is affine, meaning its only
operations are addition and multiplication-by-constant. In particular, suppose
the circuit does not contain a multiplication gate whose operands are both
non-constant. Then to decide if an input `x` is valid, each Aggregator could
evaluate `C` on its share of `x` locally, broadcast the output share to its
peers, then combine the output shares locally to recover `C(x)`. This is true
because for any `SHARES`-way secret sharing of `x` it holds that

~~~
C(x_shares[0] + ... + x_shares[SHARES-1]) =
    C(x_shares[0]) + ... + C(x_shares[SHARES-1])
~~~

(Note that, for this equality to hold, it may be necessary to scale any
constants in the circuit by `SHARES`.) However this is not the case if `C` is
not-affine (i.e., it contains at least one multiplication gate whose operands
are non-constant). In the proof system of {{BBCGGI19}}, the proof is designed to
allow the (distributed) verifier to compute the non-affine operations using only
linear operations on (its share of) the input and proof.

To make this work, the proof system is restricted to validity circuits that
exhibit a special structure. Specifically, an arithmetic circuit with "G-gates"
(see {{BBCGGI19}}, Definition 5.2) is composed of affine gates and any number of
instances of a distinguished gate `G`, which may be non-affine. We will refer to
this class of circuits as 'gadget circuits' and to `G` as the "gadget".

As an illustrative example, consider a validity circuit `C` that recognizes the
set `L = set([0], [1])`. That is, `C` takes as input a length-1 vector `x` and
returns 0 if `x[0]` is in `[0,2)` and outputs something else otherwise. This
circuit can be expressed as the following degree-2 polynomial:

~~~
C(x) = (x[0] - 1) * x[0] = x[0]^2 - x[0]
~~~

This polynomial recognizes `L` because `x[0]^2 = x[0]` is only true if `x[0] ==
0` or `x[0] == 1`. Notice that the polynomial involves a non-affine operation,
`x[0]^2`. In order to apply {{BBCGGI19}}, Theorem 4.3, the circuit needs to be
rewritten in terms of a gadget that subsumes this non-affine operation. For
example, the gadget might be multiplication:

~~~
Mul(left, right) = left * right
~~~

The validity circuit can then be rewritten in terms of `Mul` like so:

~~~
C(x[0]) = Mul(x[0], x[0]) - x[0]
~~~

The proof system of {{BBCGGI19}} allows the verifier to evaluate each instance
of the gadget (i.e., `Mul(x[0], x[0])` in our example) using a linear function
of the input and proof. The proof is constructed roughly as follows. Let `C` be
the validity circuit and suppose the gadget is arity-`L` (i.e., it has `L` input
wires.). Let `wire[j-1,k-1]` denote the value of the `j`th wire of the `k`th
call to the gadget during the evaluation of `C(x)`. Suppose there are `M` such
calls and fix distinct field elements `alpha[0], ..., alpha[M-1]`. (We will
require these points to have a special property, as we'll discuss in
{{flp-generic-overview-extensions}}; but for the moment it is only important
that they are distinct.)

The prover constructs from `wire` and `alpha` a polynomial that, when evaluated
at `alpha[k-1]`, produces the output of the `k`th call to the gadget. Let us
call this the "gadget polynomial". Polynomial evaluation is linear, which means
that, in the distributed setting, the Client can disseminate additive shares of
the gadget polynomial that the Aggregators then use to compute additive shares
of each gadget output, allowing each Aggregator to compute its share of `C(x)`
locally.

There is one more wrinkle, however: It is still possible for a malicious prover
to produce a gadget polynomial that would result in `C(x)` being computed
incorrectly, potentially resulting in an invalid input being accepted. To
prevent this, the verifier performs a probabilistic test to check that the
gadget polynomial is well-formed. This test, and the procedure for constructing
the gadget polynomial, are described in detail in {{flp-generic-construction}}.

#### Extensions {#flp-generic-overview-extensions}

The FLP described in the next section extends the proof system {{BBCGGI19}},
Section 4.2 in three ways.

First, the validity circuit in our construction includes an additional, random
input (this is the "joint randomness" derived from the input shares in Prio3;
see {{prio3-construction}}). This allows for circuit optimizations that trade a
small soundness error for a shorter proof. For example, consider a circuit that
recognizes the set of length-`N` vectors for which each element is either one or
zero. A deterministic circuit could be constructed for this language, but it
would involve a large number of multiplications that would result in a large
proof. (See the discussion in {{BBCGGI19}}, Section 5.2 for details). A much
shorter proof can be constructed for the following randomized circuit:

~~~
C(inp, r) = r * Range2(inp[0]) + ... + r^N * Range2(inp[N-1])
~~~

(Note that this is a special case of {{BBCGGI19}}, Theorem 5.2.) Here `inp` is
the length-`N` input and `r` is a random field element. The gadget circuit
`Range2` is the "range-check" polynomial described above, i.e., `Range2(x) = x^2 -
x`. The idea is that, if `inp` is valid (i.e., each `inp[j]` is in `[0,2)`),
then the circuit will evaluate to 0 regardless of the value of `r`; but if
`inp[j]` is not in `[0,2)` for some `j`, the output will be non-zero with high
probability.

The second extension implemented by our FLP allows the validity circuit to
contain multiple gadget types. (This generalization was suggested in
{{BBCGGI19}}, Remark 4.5.) For example, the following circuit is allowed, where
`Mul` and `Range2` are the gadgets defined above (the input has length `N+1`):

~~~
C(inp, r) = r * Range2(inp[0]) + ... + r^N * Range2(inp[N-1]) + \
            2^0 * inp[0]       + ... + 2^(N-1) * inp[N-1]     - \
            Mul(inp[N], inp[N])
~~~

Finally, {{BBCGGI19}}, Theorem 4.3 makes no restrictions on the choice of the
fixed points `alpha[0], ..., alpha[M-1]`, other than to require that the points
are distinct. In this document, the fixed points are chosen so that the gadget
polynomial can be constructed efficiently using the Cooley-Tukey FFT ("Fast
Fourier Transform") algorithm. Note that this requires the field to be
"FFT-friendly" as defined in {{field-fft-friendly}}.

### Validity Circuits {#flp-generic-valid}

The FLP described in {{flp-generic-construction}} is defined in terms of a
validity circuit `Valid` that implements the interface described here.

A concrete `Valid` defines the following parameters:

| Parameter      | Description                           |
|:---------------|:--------------------------------------|
| `GADGETS`      | A list of gadgets                     |
| `GADGET_CALLS` | Number of times each gadget is called |
| `INPUT_LEN`    | Length of the input                   |
| `OUTPUT_LEN`   | Length of the aggregatable output     |
| `JOINT_RAND_LEN` | Length of the random input          |
| `Measurement`  | The type of measurement               |
| `AggResult`    | Type of the aggregate result          |
| `Field`        | An FFT-friendly finite field as defined in {{field-fft-friendly}} |
{: title="Validity circuit parameters."}

Each gadget `G` in `GADGETS` defines a constant `DEGREE` that specifies the
circuit's "arithmetic degree". This is defined to be the degree of the
polynomial that computes it. For example, the `Mul` circuit in
{{flp-generic-overview}} is defined by the polynomial `Mul(x) = x * x`, which
has degree `2`. Hence, the arithmetic degree of this gadget is `2`.

Each gadget also defines a parameter `ARITY` that specifies the circuit's arity
(i.e., the number of input wires).

A concrete `Valid` provides the following methods for encoding a measurement as
an input vector, truncating an input vector to the length of an aggregatable
output, and converting an aggregated output to an aggregate result:

* `Valid.encode(measurement: Measurement) -> Vec[Field]` returns a vector of
  length `INPUT_LEN` representing a measurement.

* `Valid.truncate(input: Vec[Field]) -> Vec[Field]` returns a vector of length
  `OUTPUT_LEN` representing an aggregatable output.

* `Valid.decode(output: Vec[Field], num_measurements: Unsigned) -> AggResult`
  returns an aggregate result.

Finally, the following class methods are derived for each concrete `Valid`:

~~~
# Length of the prover randomness.
def prove_rand_len(Valid):
    return sum(map(lambda g: g.ARITY, Valid.GADGETS))

# Length of the query randomness.
def query_rand_len(Valid):
    return len(Valid.GADGETS)

# Length of the proof.
def proof_len(Valid):
    length = 0
    for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
        P = next_power_of_2(1 + g_calls)
        length += g.ARITY + g.DEGREE * (P - 1) + 1
    return length

# Length of the verifier message.
def verifier_len(Valid):
    length = 1
    for g in Valid.GADGETS:
        length += g.ARITY + 1
    return length
~~~
{: title="Derived methods for validity circuits."}

### Construction {#flp-generic-construction}

This section specifies `FlpGeneric`, an implementation of the `Flp` interface
({{flp}}). It has as a generic parameter a validity circuit `Valid` implementing
the interface defined in {{flp-generic-valid}}.

> NOTE A reference implementation can be found in
> https://github.com/cfrg/draft-irtf-cfrg-vdaf/blob/main/poc/flp_generic.sage.

The FLP parameters for `FlpGeneric` are defined in {{flp-generic-param}}. The
required methods for generating the proof, generating the verifier, and deciding
validity are specified in the remaining subsections.

In the remainder, we let `[n]` denote the set `{1, ..., n}` for positive integer
`n`. We also define the following constants:

* Let `H = len(Valid.GADGETS)`
* For each `i` in `[H]`:
    * Let `G_i = Valid.GADGETS[i]`
    * Let `L_i = Valid.GADGETS[i].ARITY`
    * Let `M_i = Valid.GADGET_CALLS[i]`
    * Let `P_i = next_power_of_2(M_i+1)`
    * Let `alpha_i = Field.gen()^(Field.GEN_ORDER / P_i)`

| Parameter        | Value               |
|:-----------------|:--------------------|
| `PROVE_RAND_LEN` | `Valid.prove_rand_len()` (see {{flp-generic-valid}}) |
| `QUERY_RAND_LEN` | `Valid.query_rand_len()` (see {{flp-generic-valid}}) |
| `JOINT_RAND_LEN` | `Valid.JOINT_RAND_LEN` |
| `INPUT_LEN`      | `Valid.INPUT_LEN`   |
| `OUTPUT_LEN`     | `Valid.OUTPUT_LEN`  |
| `PROOF_LEN`      | `Valid.proof_len()` (see {{flp-generic-valid}}) |
| `VERIFIER_LEN`   | `Valid.verifier_len()` (see {{flp-generic-valid}}) |
| `Measurement`    | `Valid.Measurement` |
| `Field`          | `Valid.Field`       |
{: #flp-generic-param title="FLP Parameters of FlpGeneric."}

#### Proof Generation {#flp-generic-construction-prove}

On input `inp`, `prove_rand`, and `joint_rand`, the proof is computed as
follows:

1. For each `i` in `[H]` create an empty table `wire_i`.

1. Partition the prover randomness `prove_rand` into subvectors `seed_1, ...,
   seed_H` where `len(seed_i) == L_i` for all `i` in `[H]`. Let us call these
   the "wire seeds" of each gadget.

1. Evaluate `Valid` on input of `inp` and `joint_rand`, recording the inputs of
   each gadget in the corresponding table. Specifically, for every `i` in `[H]`,
   set `wire_i[j-1,k-1]` to the value on the `j`th wire into the `k`th call to
   gadget `G_i`.

1. Compute the "wire polynomials". That is, for every `i` in `[H]` and `j` in
   `[L_i]`, construct `poly_wire_i[j-1]`, the `j`th wire polynomial for the
   `i`th gadget, as follows:

    * Let `w = [seed_i[j-1], wire_i[j-1,0], ..., wire_i[j-1,M_i-1]]`.

    * Let `padded_w = w + Field.zeros(P_i - len(w))`.

    > NOTE We pad `w` to the nearest power of 2 so that we can use FFT for
    > interpolating the wire polynomials. Perhaps there is some clever math for
    > picking `wire_inp` in a way that avoids having to pad.

    * Let `poly_wire_i[j-1]` be the lowest degree polynomial for which
      `poly_wire_i[j-1](alpha_i^k) == padded_w[k]` for all `k` in `[P_i]`.

1. Compute the "gadget polynomials". That is, for every `i` in `[H]`:

    * Let `poly_gadget_i = G_i(poly_wire_i[0], ..., poly_wire_i[L_i-1])`. That
      is, evaluate the circuit `G_i` on the wire polynomials for the `i`th
      gadget. (Arithmetic is in the ring of polynomials over `Field`.)

The proof is the vector `proof = seed_1 + coeff_1 + ... + seed_H + coeff_H`,
where `coeff_i` is the vector of coefficients of `poly_gadget_i` for each `i` in
`[H]`.

#### Query Generation {#flp-generic-construction-query}

On input of `inp`, `proof`, `query_rand`, and `joint_rand`, the verifier message
is generated as follows:

1. For every `i` in `[H]` create an empty table `wire_i`.

1. Partition `proof` into the subvectors `seed_1`, `coeff_1`, ..., `seed_H`,
   `coeff_H` defined in {{flp-generic-construction-prove}}.

1. Evaluate `Valid` on input of `inp` and `joint_rand`, recording the inputs of
   each gadget in the corresponding table. This step is similar to the prover's
   step (3.) except the verifier does not evaluate the gadgets. Instead, it
   computes the output of the `k`th call to `G_i` by evaluating
   `poly_gadget_i(alpha_i^k)`. Let `v` denote the output of the circuit
   evaluation.

1. Compute the wire polynomials just as in the prover's step (4.).

1. Compute the tests for well-formedness of the gadget polynomials. That is, for
   every `i` in `[H]`:

    * Let `t = query_rand[i]`. Check if `t^(P_i) == 1`: If so, then raise
      ERR_ABORT and halt. (This prevents the verifier from inadvertently leaking
      a gadget output in the verifier message.)

    * Let `y_i = poly_gadget_i(t)`.

    * For each `j` in `[0,L_i)` let `x_i[j-1] = poly_wire_i[j-1](t)`.

The verifier message is the vector `verifier = [v] + x_1 + [y_1] + ... + x_H +
[y_H]`.

#### Decision

On input of vector `verifier`, the verifier decides if the input is valid as
follows:

1. Parse `verifier` into `v`, `x_1`, `y_1`, ..., `x_H`, `y_H` as defined in
   {{flp-generic-construction-query}}.

1. Check for well-formedness of the gadget polynomials. For every `i` in `[H]`:

    * Let `z = G_i(x_i)`. That is, evaluate the circuit `G_i` on `x_i` and set
      `z` to the output.

    * If `z != y_i`, then return `False` and halt.

1. Return `True` if `v == 0` and `False` otherwise.

#### Encoding

The FLP encoding and truncation methods invoke `Valid.encode`,
`Valid.truncate`, and `Valid.decode` in the natural way.

## Instantiations {#prio3-instantiations}

This section specifies instantiations of Prio3 for various measurement types.
Each uses `FlpGeneric` as the FLP ({{flp-generic}}) and is determined by a
validity circuit ({{flp-generic-valid}}) and a PRG ({{prg}}). Test vectors for
each can be found in {{test-vectors}}.

> NOTE Reference implementations of each of these VDAFs can be found in
> https://github.com/cfrg/draft-irtf-cfrg-vdaf/blob/main/poc/vdaf_prio3.sage.

### Prio3Aes128Count

Our first instance of Prio3 is for a simple counter: Each measurement is either
one or zero and the aggregate result is the sum of the measurements.

This instance uses `PrgAes128` ({{prg-aes128}}) as its PRG. Its validity
circuit, denoted `Count`, uses `Field64` ({{field64}}) as its finite field. Its
gadget, denoted `Mul`, is the degree-2, arity-2 gadget defined as

~~~
def Mul(x, y):
    return x * y
~~~

The validity circuit is defined as

~~~
def Count(inp: Vec[Field64]):
    return Mul(inp[0], inp[0]) - inp[0]
~~~

The measurement is encoded and decoded as a singleton vector in the natural
way. The parameters for this circuit are summarized below.

| Parameter        | Value                        |
|:-----------------|:-----------------------------|
| `GADGETS`        | `[Mul]`                      |
| `GADGET_CALLS`   | `[1]`                        |
| `INPUT_LEN`      | `1`                          |
| `OUTPUT_LEN`     | `1`                          |
| `JOINT_RAND_LEN` | `0`                          |
| `Measurement`    | `Unsigned`, in range `[0,2)` |
| `AggResult`      | `Unsigned`                   |
| `Field`          | `Field64` ({{field64}})      |
{: title="Parameters of validity circuit Count."}

### Prio3Aes128Sum {#prio3-sum}

The next instance of Prio3 supports summing of integers in a pre-determined
range. Each measurement is an integer in range `[0, 2^bits)`, where `bits` is an
associated parameter.

This instance of Prio3 uses `PrgAes128` ({{prg-aes128}}) as its PRG.
Its validity circuit, denoted `Sum`, uses `Field128` ({{field128}}) as its
finite field. The measurement is encoded as a length-`bits` vector of field
elements, where the `l`th element of the vector represents the `l`th bit of the
summand:

~~~
def encode(Sum, measurement: Integer):
    if 0 > measurement or measurement >= 2^Sum.INPUT_LEN:
        raise ERR_INPUT

    encoded = []
    for l in range(Sum.INPUT_LEN):
        encoded.append(Sum.Field((measurement >> l) & 1))
    return encoded

def truncate(Sum, inp):
    decoded = Sum.Field(0)
    for (l, b) in enumerate(inp):
        w = Sum.Field(1 << l)
        decoded += w * b
    return [decoded]

def decode(Sum, output, _num_measurements):
    return output[0].as_unsigned()
~~~

The validity circuit checks that the input consists of ones and zeros. Its
gadget, denoted `Range2`, is the degree-2, arity-1 gadget defined as

~~~
def Range2(x):
    return x^2 - x
~~~

The validity circuit is defined as

~~~
def Sum(inp: Vec[Field128], joint_rand: Vec[Field128]):
    out = Field128(0)
    r = joint_rand[0]
    for x in inp:
        out += r * Range2(x)
        r *= joint_rand[0]
    return out
~~~

| Parameter        | Value                        |
|:-----------------|:-----------------------------|
| `GADGETS`        | `[Range2]`                   |
| `GADGET_CALLS`   | `[bits]`                     |
| `INPUT_LEN`      | `bits`                       |
| `OUTPUT_LEN`     | `1`                          |
| `JOINT_RAND_LEN` | `1`                          |
| `Measurement`    | `Unsigned`, in range `[0, 2^bits)` |
| `AggResult`      | `Unsigned`                   |
| `Field`          | `Field128` ({{field128}})    |
{: title="Parameters of validity circuit Sum."}

### Prio3Aes128Histogram

This instance of Prio3 allows for estimating the distribution of the
measurements by computing a simple histogram. Each measurement is an arbitrary
integer and the aggregate result counts the number of measurements that fall in
a set of fixed buckets.

This instance of Prio3 uses `PrgAes128` ({{prg-aes128}}) as its PRG. Its
validity circuit, denoted `Histogram`, uses `Field128` ({{field128}}) as its
finite field. The measurement is encoded as a one-hot vector representing the
bucket into which the measurement falls (let `bucket` denote a sequence of
monotonically increasing integers):

~~~
def encode(Histogram, measurement: Integer):
    boundaries = buckets + [Infinity]
    encoded = [Field128(0) for _ in range(len(boundaries))]
    for i in range(len(boundaries)):
        if measurement <= boundaries[i]:
            encoded[i] = Field128(1)
            return encoded

def truncate(Histogram, inp: Vec[Field128]):
    return inp

def decode(Histogram, output: Vec[Field128], _num_measurements):
    return [bucket_count.as_unsigned() for bucket_count in output]
~~~

The validity circuit uses `Range2` (see {{prio3-sum}}) as its single gadget. It
checks for one-hotness in two steps, as follows:

~~~
def Histogram(inp: Vec[Field128],
              joint_rand: Vec[Field128],
              num_shares: Unsigned):
    # Check that each bucket is one or zero.
    range_check = Field128(0)
    r = joint_rand[0]
    for x in inp:
        range_check += r * Range2(x)
        r *= joint_rand[0]

    # Check that the buckets sum to 1.
    sum_check = -Field128(1) * Field128(num_shares).inv()
    for b in inp:
        sum_check += b

    out = joint_rand[1]   * range_check + \
          joint_rand[1]^2 * sum_check
    return out
~~~

Note that this circuit depends on the number of shares into which the input is
sharded. This is provided to the FLP by Prio3.

| Parameter        | Value                     |
|:-----------------|:--------------------------|
| `GADGETS`        | `[Range2]`                |
| `GADGET_CALLS`   | `[buckets + 1]`           |
| `INPUT_LEN`      | `buckets + 1`             |
| `OUTPUT_LEN`     | `buckets + 1`             |
| `JOINT_RAND_LEN` | `2`                       |
| `Measurement`    | `Integer`                 |
| `AggResult`      | `Vec[Unsigned]`           |
| `Field`          | `Field128` ({{field128}}) |
{: title="Parameters of validity circuit Histogram."}

# Poplar1 {#poplar1}

> NOTE This construction has not undergone significant security analysis.

This section specifies Poplar1, a VDAF for the following task. Each Client holds
a string of length `BITS` and the Aggregators hold a set of `l`-bit strings,
where `l <= BITS`. We will refer to the latter as the set of "candidate
prefixes". The Aggregators' goal is to count how many inputs are prefixed by
each candidate prefix.

This functionality is the core component of the Poplar protocol {{BBCGGI21}}. At
a high level, the protocol works as follows.

1. Each Client splits its input string into input shares and sends one share to
   each Aggregator.
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

Poplar1 is constructed from an "Incremental Distributed Point Function (IDPF)",
a primitive described by {{BBCGGI21}} that generalizes the notion of a
Distributed Point Function (DPF) {{GI14}}. Briefly, a DPF is used to distribute
the computation of a "point function", a function that evaluates to zero on
every input except at a programmable "point". The computation is distributed in
such a way that no one party knows either the point or what it evaluates to.

An IDPF generalizes this "point" to a path on a full binary tree from the root
to one of the leaves. It is evaluated on an "index" representing a unique node
of the tree. If the node is on the programmed path, then function evaluates to
to a non-zero value; otherwise it evaluates to zero. This structure allows an
IDPF to provide the functionality required for the above protocol, while at the
same time ensuring the same degree of privacy as a DPF.

Poplar1 composes an IDPF with the "secure sketching" protocol of {{BBCGGI21}}.
This protocol ensures that evaluating a set of input shares on a unique set of
candidate prefixes results in shares of a "one-hot" vector, i.e., a vector that
is zero everywhere except for one element, which is equal to one.

The remainder of this section is structured as follows. IDPFs are defined in
{{idpf}}; a concrete instantiation is given {{idpf-poplar}}. The Poplar1 VDAF is
defined in {{poplar1-construction}} in terms of a generic IDPF. Finally, a
concrete instantiation of Poplar1 is specified in {{poplar1-instantiation}};
test vectors can be found in {{test-vectors}}.

## Incremental Distributed Point Functions (IDPFs) {#idpf}

An IDPF is defined over a domain of size `2^BITS`, where `BITS` is constant
defined by the IDPF. Indexes into the IDPF tree are encoded as integers in range
`[0, 2^BITS)`. The Client specifies an index `alpha` and a vector of
values `beta`, one for each "level" `L` in range `[0, BITS)`. The key generation
algorithm generates one IDPF "key" for each Aggregator. When evaluated at level
`L` and index `0 <= prefix < 2^L`, each IDPF key returns an additive share of
`beta[L]` if `prefix` is the `L`-bit prefix of `alpha` and shares of zero
otherwise.

An index `x` is defined to be a prefix of another index `y` as follows. Let
`LSB(x, N)` denote the least significant `N` bits of positive integer `x`. By
definition, a positive integer `0 <= x < 2^L` is said to be the length-`L`
prefix of positive integer `0 <= y < 2^BITS` if `LSB(x, L)` is equal to the most
significant `L` bits of `LSB(y, BITS)`, For example, 6 (110 in binary) is the
length-3 prefix of 25 (11001), but 7 (111) is not.

Each of the programmed points `beta` is a vector of elements of some finite
field. We distinguish two types of fields: One for inner nodes (denoted
`Idpf.FieldInner`), and one for leaf nodes (`Idpf.FieldLeaf`). (Our
instantiation of Poplar1 ({{poplar1-instantiation}}) will use a much larger
field for leaf nodes than for inner nodes. This is to ensure the IDPF is
"extractable" as defined in {{BBCGGI21}}, Definition 1.)

A concrete IDPF defines the types and constants enumerated in {{idpf-param}}. In
the remainder we write `Idpf.Vec` as shorthand for the type
`Union[Vec[Vec[Idpf.FieldInner]], Vec[Vec[Idpf.FieldLeaf]]]`. (This type denotes
either a vector of inner node field elements or leaf node field elements.) The
scheme is comprised of the following algorithms:

* `Idpf.gen(alpha: Unsigned, beta_inner: Vec[Vec[Idpf.FieldInner]], beta_leaf:
  Vec[Idpf.FieldLeaf]) -> (Bytes, Vec[Bytes])` is the randomized IDPF-key
  generation algorithm. Its inputs are the index `alpha` and the values `beta`.
  The value of `alpha` MUST be in range `[0, 2^BITS)`. The output is a public
  part that is sent to all aggregators and a vector of private IDPF keys, one
  for each aggregator.

* `Idpf.eval(agg_id: Unsigned, public_share: Bytes, key: Bytes, level: Unsigned,
  prefixes: Vec[Unsigned]) -> Idpf.Vec` is the deterministic, stateless
  IDPF-key evaluation algorithm run by each Aggregator. Its inputs are the
  Aggregator's unique identifier, the public share distributed to all of the
  Aggregators, the Aggregator's IDPF key, the "level" at which to evaluate the
  IDPF, and the sequence of candidate prefixes. It returns the share of the
  value corresponding to each candidate prefix.

  The output type depends on the value of `level`: If `level < Idpf.BITS-1`, the
  output is the value for an inner node, which has type
  `Vec[Vec[Idpf.FieldInner]]`; otherwise, if `level == Idpf.BITS-1`, then the
  output is the value for a leaf node, which has type
  `Vec[Vec[Idpf.FieldLeaf]]`.

  The value of `level` MUST be in range `[0, BITS)`. The indexes in `prefixes`
  MUST all be distinct and in range `[0, 2^level)`.

  Applications MUST ensure that the Aggregator's identifier is equal to the
  integer in range `[0, SHARES)` that matches the index of `key` in the sequence
  of IDPF keys output by the Client.

In addition, the following method is derived for each concrete `Idpf`:

~~~
def current_field(Idpf, level):
    return Idpf.FieldInner if level < Idpf.BITS-1 \
                else Idpf.FieldLeaf
~~~

Finally, an implementation note. The interface for IDPFs specified here is
stateless, in the sense that there is no state carried between IDPF evaluations.
This is to align the IDPF syntax with the VDAF abstraction boundary, which does
not include shared state across across VDAF evaluations. In practice, of course,
it will often be beneficial to expose a stateful API for IDPFs and carry the
state across evaluations. See {{idpf-poplar}} for details.

| Parameter  | Description               |
|:-----------|:--------------------------|
| SHARES     | Number of IDPF keys output by IDPF-key generator |
| BITS       | Length in bits of each input string |
| VALUE_LEN  | Number of field elements of each output value |
| KEY_SIZE   | Size in bytes of each IDPF key |
| FieldInner | Implementation of `Field` ({{field}}) used for values of inner nodes |
| FieldLeaf  | Implementation of `Field` used for values of leaf nodes |
| Prg        | Implementation of `Prg` ({{prg}}) |
{: #idpf-param title="Constants and types defined by a concrete IDPF."}

## Construction {#poplar1-construction}

This section specifies `Poplar1`, an implementation of the `Vdaf` interface
({{vdaf}}). It is defined in terms of any `Idpf` ({{idpf}}) for which
`Idpf.SHARES == 2` and `Idpf.VALUE_LEN == 2`. The associated constants and types
required by the `Vdaf` interface are defined in {{poplar1-param}}. The methods
required for sharding, preparation, aggregation, and unsharding are described in
the remaining subsections.

| Parameter         | Value             |
|:------------------|:------------------|
| `VERIFY_KEY_SIZE` | `Idpf.Prg.SEED_SIZE` |
| `ROUNDS`          | `2` |
| `SHARES`          | `2` |
| `Measurement`     | `Unsigned` |
| `AggParam`        | `Tuple[Unsigned, Vec[Unsigned]]` |
| `Prep`            | `Tuple[Bytes, Unsigned, Idpf.Vec]` |
| `OutShare`        | `Idpf.Vec` |
| `AggResult`       | `Vec[Unsigned]` |
{: #poplar1-param title="Associated parameters for the Poplar1 VDAF."}

### Client

The client's input is an IDPF index, denoted `alpha`. The programmed IDPF values
are pairs of field elements `(1, k)` where each `k` is chosen at random. This
random value is used as part of the secure sketching protocol of {{BBCGGI21}},
Appendix C.4. After evaluating their IDPF key shares on a given sequence of
candidate prefixes, the sketching protocol is used by the Aggregators to verify
that they hold shares of a one-hot vector. In addition, for each level of the
tree, the prover generates random elements `a`, `b`, and `c` and computes

~~~
    A = -2*a + k
    B = a^2 + b - k*a + c
~~~

and sends additive shares of `a`, `b`, `c`, `A` and `B` to the Aggregators.
Putting everything together, the input-distribution algorithm is defined as
follows. Function `encode_input_shares` is defined in {{poplar1-helper-functions}}.


~~~
def measurement_to_input_shares(Poplar1, measurement):
    dst = VERSION + b' poplar1'
    prg = Poplar1.Idpf.Prg(
        gen_rand(Poplar1.Idpf.Prg.SEED_SIZE), dst + byte(255))

    # Construct the IDPF values for each level of the IDPF tree.
    # Each "data" value is 1; in addition, the Client generates
    # a random "authenticator" value used by the Aggregators to
    # compute the sketch during preparation. This sketch is used
    # to verify the one-hotness of their output shares.
    beta_inner = [
        [Poplar1.Idpf.FieldInner(1), k] \
            for k in prg.next_vec(Poplar1.Idpf.FieldInner,
                                  Poplar1.Idpf.BITS - 1) ]
    beta_leaf = [Poplar1.Idpf.FieldLeaf(1)] + \
        prg.next_vec(Poplar1.Idpf.FieldLeaf, 1)

    # Generate the IDPF keys.
    (public_share, keys) = \
        Poplar1.Idpf.gen(measurement, beta_inner, beta_leaf)

    # Generate correlated randomness used by the Aggregators to
    # compute a sketch over their output shares. PRG seeds are
    # used to encode shares of the `(a, b, c)` triples.
    # (See [BBCGGI21, Appendix C.4].)
    corr_seed = [
        gen_rand(Poplar1.Idpf.Prg.SEED_SIZE),
        gen_rand(Poplar1.Idpf.Prg.SEED_SIZE),
    ]
    corr_prg = [
        Poplar1.Idpf.Prg(corr_seed[0], dst + byte(0)),
        Poplar1.Idpf.Prg(corr_seed[1], dst + byte(1)),
    ]

    # For each level of the IDPF tree, shares of the `(A, B)`
    # pairs are computed from the corresponding `(a, b, c)`
    # triple and authenticator value `k`.
    corr_inner = [[], []]
    for level in range(Poplar1.Idpf.BITS):
        Field = Poplar1.Idpf.current_field(level)
        k = beta_inner[level][1] if level < Poplar1.Idpf.BITS - 1 \
            else beta_leaf[1]
        (a, b, c) = vec_add(corr_prg[0].next_vec(Field, 3),
                            corr_prg[1].next_vec(Field, 3))
        A = -Field(2) * a + k
        B = a^2 + b - a * k + c
        corr1 = prg.next_vec(Field, 2)
        corr0 = vec_sub([A, B], corr1)
        if level < Poplar1.Idpf.BITS - 1:
            corr_inner[0] += corr0
            corr_inner[1] += corr1
        else:
            corr_leaf = [corr0, corr1]

    # Each input share consists of the Aggregator's IDPF key
    # and a share of the correlated randomness.
    return (public_share,
            Poplar1.encode_input_shares(
                keys, corr_seed, corr_inner, corr_leaf))
~~~
{: #poplar1-mes2inp title="The input-distribution algorithm for Poplar1."}

### Preparation

The aggregation parameter encodes a sequence of candidate prefixes. When an
Aggregator receives an input share from the Client, it begins by evaluating its
IDPF share on each candidate prefix, recovering a `data_share` and `auth_share`
for each. The Aggregators use these and the correlation shares provided by the
Client to verify that the sequence of `data_share` values are additive shares of
a one-hot vector.

The algorithms below make use of auxiliary functions `verify_context()` and
`decode_input_share()` defined in {{poplar1-helper-functions}}.

~~~
def prep_init(Poplar1, verify_key, agg_id, agg_param,
              nonce, public_share, input_share):
    dst = VERSION + b' poplar1'
    (level, prefixes) = agg_param
    (key, corr_seed, corr_inner, corr_leaf) = \
        Poplar1.decode_input_share(input_share)

    # Evaluate the IDPF key at the given set of prefixes.
    value = Poplar1.Idpf.eval(
        agg_id, public_share, key, level, prefixes)

    # Get correlation shares for the given level of the IDPF tree.
    #
    # Implementation note: Computing the shares of `(a, b, c)`
    # requires expanding PRG seeds into a vector of field elements
    # of length proportional to the level of the tree. Typically
    # the IDPF will be evaluated incrementally beginning with
    # `level == 0`. Implementations can save computation by
    # storing the intermediate PRG state between evaluations.
    corr_prg = Poplar1.Idpf.Prg(corr_seed, dst + byte(agg_id))
    for current_level in range(level+1):
        Field = Poplar1.Idpf.current_field(current_level)
        (a_share, b_share, c_share) = corr_prg.next_vec(Field, 3)
    (A_share, B_share) = corr_inner[2*level:2*(level+1)] \
        if level < Poplar1.Idpf.BITS - 1 else corr_leaf

    # Compute the Aggregator's first round of the sketch. These are
    # called the "masked input values" [BBCGGI21, Appendix C.4].
    Field = Poplar1.Idpf.current_field(level)
    verify_rand_prg = Poplar1.Idpf.Prg(verify_key,
        dst + Poplar1.verify_context(nonce, level, prefixes))
    verify_rand = verify_rand_prg.next_vec(Field, len(prefixes))
    sketch_share = [a_share, b_share, c_share]
    out_share = []
    for (i, r) in enumerate(verify_rand):
        (data_share, auth_share) = value[i]
        sketch_share[0] += data_share * r
        sketch_share[1] += data_share * r^2
        sketch_share[2] += auth_share * r
        out_share.append(data_share)

    prep_mem = sketch_share \
                + [A_share, B_share, Field(agg_id)] \
                + out_share
    return (b'ready', level, prep_mem)

def prep_next(Poplar1, prep_state, opt_sketch):
    (step, level, prep_mem) = prep_state
    Field = Poplar1.Idpf.current_field(level)

    # Aggregators exchange masked input values (step (3.)
    # of [BBCGGI21, Appendix C.4]).
    if step == b'ready' and opt_sketch == None:
        sketch_share, prep_mem = prep_mem[:3], prep_mem[3:]
        return ((b'sketch round 1', level, prep_mem),
                Field.encode_vec(sketch_share))

    # Aggregators exchange evaluated shares (step (4.)).
    elif step == b'sketch round 1' and opt_sketch != None:
        prev_sketch = Field.decode_vec(opt_sketch)
        if len(prev_sketch) == 0:
            prev_sketch = Field.zeros(3)
        elif len(prev_sketch) != 3:
            raise ERR_INPUT # prep message malformed
        (A_share, B_share, agg_id), prep_mem = \
            prep_mem[:3], prep_mem[3:]
        sketch_share = [
            agg_id * (prev_sketch[0]^2 \
                        - prev_sketch[1]
                        - prev_sketch[2]) \
                + A_share * prev_sketch[0] \
                + B_share
        ]
        return ((b'sketch round 2', level, prep_mem),
                Field.encode_vec(sketch_share))

    elif step == b'sketch round 2' and opt_sketch != None:
        prev_sketch = Field.decode_vec(opt_sketch)
        if len(prev_sketch) == 0:
            prev_sketch = Field.zeros(1)
        elif len(prev_sketch) != 1:
            raise ERR_INPUT # prep message malformed
        if prev_sketch[0] != Field(0):
            raise ERR_VERIFY
        return prep_mem # Output shares

    raise ERR_INPUT # unexpected input

def prep_shares_to_prep(Poplar1, agg_param, prep_shares):
    if len(prep_shares) != 2:
        raise ERR_INPUT # unexpected number of prep shares
    (level, _) = agg_param
    Field = Poplar1.Idpf.current_field(level)
    sketch = vec_add(Field.decode_vec(prep_shares[0]),
                     Field.decode_vec(prep_shares[1]))
    if sketch == Field.zeros(len(sketch)):
        # In order to reduce communication overhead, let the
        # empty string denote the zero vector of the required
        # length.
        return b''
    return Field.encode_vec(sketch)
~~~
{: #poplar1-prep-state title="Preparation state for Poplar1."}

### Aggregation

Aggregation involves simply adding up the output shares.

~~~
def out_shares_to_agg_share(Poplar1, agg_param, out_shares):
    (level, prefixes) = agg_param
    Field = Poplar1.Idpf.current_field(level)
    agg_share = Field.zeros(len(prefixes))
    for out_share in out_shares:
        agg_share = vec_add(agg_share, out_share)
    return Field.encode_vec(agg_share)
~~~
{: #poplar1-out2agg title="Aggregation algorithm for Poplar1."}

### Unsharding

Finally, the Collector unshards the aggregate result by adding up the aggregate
shares.

~~~
def agg_shares_to_result(Poplar1, agg_param,
                         agg_shares, _num_measurements):
    (level, prefixes) = agg_param
    Field = Poplar1.Idpf.current_field(level)
    agg = Field.zeros(len(prefixes))
    for agg_share in agg_shares:
        agg = vec_add(agg, Field.decode_vec(agg_share))
    return list(map(lambda x: x.as_unsigned(), agg))
~~~
{: #poplar1-agg-output title="Computation of the aggregate result for Poplar1."}

### Auxiliary Functions {#poplar1-helper-functions}

~~~
def encode_input_shares(Poplar1, keys,
                        corr_seed, corr_inner, corr_leaf):
    input_shares = []
    for (key, seed, inner, leaf) in zip(keys,
                                        corr_seed,
                                        corr_inner,
                                        corr_leaf):
        encoded = Bytes()
        encoded += key
        encoded += seed
        encoded += Poplar1.Idpf.FieldInner.encode_vec(inner)
        encoded += Poplar1.Idpf.FieldLeaf.encode_vec(leaf)
        input_shares.append(encoded)
    return input_shares

def decode_input_share(Poplar1, encoded):
    l = Poplar1.Idpf.KEY_SIZE
    key, encoded = encoded[:l], encoded[l:]
    l = Poplar1.Idpf.Prg.SEED_SIZE
    corr_seed, encoded = encoded[:l], encoded[l:]
    l = Poplar1.Idpf.FieldInner.ENCODED_SIZE \
        * 2 * (Poplar1.Idpf.BITS - 1)
    encoded_corr_inner, encoded = encoded[:l], encoded[l:]
    corr_inner = Poplar1.Idpf.FieldInner.decode_vec(
        encoded_corr_inner)
    l = Poplar1.Idpf.FieldLeaf.ENCODED_SIZE * 2
    encoded_corr_leaf, encoded = encoded[:l], encoded[l:]
    corr_leaf = Poplar1.Idpf.FieldLeaf.decode_vec(
        encoded_corr_leaf)
    if len(encoded) != 0:
        raise ERR_INPUT
    return (key, corr_seed, corr_inner, corr_leaf)

def encode_agg_param(Poplar1, level, prefixes):
    if level > 2^16 - 1:
        raise ERR_INPUT # level too deep
    if len(prefixes) > 2^16 - 1:
        raise ERR_INPUT # too many prefixes
    encoded = Bytes()
    encoded += I2OSP(level, 2)
    encoded += I2OSP(len(prefixes), 2)
    packed = 0
    for (i, prefix) in enumerate(prefixes):
        packed |= prefix << ((level+1) * i)
    l = floor(((level+1) * len(prefixes) + 7) / 8)
    encoded += I2OSP(packed, l)
    return encoded

def verify_context(Poplar1, nonce, level, prefixes):
    if len(nonce) > 255:
        raise ERR_INPUT # nonce too long
    context = Bytes()
    context += byte(254)
    context += byte(len(nonce))
    context += nonce
    context += Poplar1.encode_agg_param(level, prefixes)
    return context
~~~
{: #poplar1-helpers title="Helper functions for Poplar1."}

## The IDPF scheme of {{BBCGGI21}} {#idpf-poplar}

In this section we specify a concrete IDPF, called IdpfPoplar, suitable for
instantiating Poplar1. The scheme gets its name from the name of the protocol of
{{BBCGGI21}}.

> TODO We should consider giving `IdpfPoplar` a more distinctive name.

The constant and type definitions required by the `Idpf` interface are given in
{{idpf-poplar-param}}.

| Parameter  | Value                     |
|:-----------|:--------------------------|
| SHARES     | `2`                       |
| BITS       | any positive integer      |
| VALUE_LEN  | any positive integer      |
| KEY_SIZE   | `Prg.SEED_SIZE`           |
| FieldInner | `Field64` ({{field64}})   |
| FieldLeaf  | `Field255` ({{field255}}) |
| Prg        | any implementation of `Prg` ({{prg}}) |
{: #idpf-poplar-param title="Constants and type definitions for IdpfPoplar."}

### Key Generation

> TODO Describe the construction in prose, beginning with a gentle introduction
> to the high level idea.

The description of the IDPF-key generation algorithm makes use of auxiliary
functions `extend()`, `convert()`, and `encode_public_share()` defined in
{{idpf-poplar-helper-functions}}. In the following, we let `Field2` denote the
field `GF(2)`.

~~~
def gen(IpdfPoplar, alpha, beta_inner, beta_leaf):
    if alpha >= 2^IdpfPoplar.BITS:
        raise ERR_INPUT # alpha too long
    if len(beta_inner) != IdpfPoplar.BITS - 1:
        raise ERR_INPUT # beta_inner vector is the wrong size

    init_seed = [
        gen_rand(IdpfPoplar.Prg.SEED_SIZE),
        gen_rand(IdpfPoplar.Prg.SEED_SIZE),
    ]

    seed = init_seed.copy()
    ctrl = [Field2(0), Field2(1)]
    correction_words = []
    for level in range(IdpfPoplar.BITS):
        keep = (alpha >> (IdpfPoplar.BITS - level - 1)) & 1
        lose = 1 - keep
        bit = Field2(keep)

        (s0, t0) = IdpfPoplar.extend(seed[0])
        (s1, t1) = IdpfPoplar.extend(seed[1])
        seed_cw = xor(s0[lose], s1[lose])
        ctrl_cw = (
            t0[0] + t1[0] + bit + Field2(1),
            t0[1] + t1[1] + bit,
        )

        x0 = xor(s0[keep], seed_cw) if ctrl[0] == Field2(1) \
                else s0[keep]
        x1 = xor(s1[keep], seed_cw) if ctrl[1] == Field2(1) \
                else s1[keep]
        (seed[0], w0) = IdpfPoplar.convert(level, x0)
        (seed[1], w1) = IdpfPoplar.convert(level, x1)
        ctrl[0] = t0[keep] + ctrl[0] * ctrl_cw[keep]
        ctrl[1] = t1[keep] + ctrl[1] * ctrl_cw[keep]

        b = beta_inner[level] if level < IdpfPoplar.BITS-1 \
                else beta_leaf
        if len(b) != IdpfPoplar.VALUE_LEN:
            raise ERR_INPUT # beta too long or too short

        w_cw = vec_add(vec_sub(b, w0), w1)
        if ctrl[1] == Field2(1):
            w_cw = vec_neg(w_cw)
        correction_words.append((seed_cw, ctrl_cw, w_cw))

    public_share = IdpfPoplar.encode_public_share(correction_words)
    return (public_share, init_seed)
~~~
{: #idpf-poplar-gen title="IDPF-key generation algorithm of IdpfPoplar."}

### Key Evaluation

> TODO Describe in prose how IDPF-key evaluation algorithm works.

The description of the IDPF-evaluation algorithm makes use of auxiliary
functions `extend()`, `convert()`, and `decode_public_share()` defined in
{{idpf-poplar-helper-functions}}.

~~~
def eval(IdpfPoplar, agg_id, public_share, init_seed,
         level, prefixes):
    if agg_id >= IdpfPoplar.SHARES:
        raise ERR_INPUT # invalid aggregator ID
    if level >= IdpfPoplar.BITS:
        raise ERR_INPUT # level too deep
    if len(set(prefixes)) != len(prefixes):
        raise ERR_INPUT # candidate prefixes are non-unique

    correction_words = IdpfPoplar.decode_public_share(public_share)
    out_share = []
    for prefix in prefixes:
        if prefix >= 2^(level+1):
            raise ERR_INPUT # prefix too long

        # The Aggregator's output share is the value of a node of
        # the IDPF tree at the given `level`. The node's value is
        # computed by traversing the path defined by the candidate
        # `prefix`. Each node in the tree is represented by a seed
        # (`seed`) and a set of control bits (`ctrl`).
        seed = init_seed
        ctrl = Field2(agg_id)
        for current_level in range(level+1):
            bit = (prefix >> (level - current_level)) & 1

            # Implementation note: Typically the current round of
            # candidate prefixes would have been derived from
            # aggregate results computed during previous rounds. For
            # example, when using `IdpfPoplar` to compute heavy
            # hitters, a string whose hit count exceeded the given
            # threshold in the last round would be the prefix of each
            # `prefix` in the current round. (See [BBCGGI21,
            # Section 5.1].) In this case, part of the path would
            # have already been traversed.
            #
            # Re-computing nodes along previously traversed paths is
            # wasteful. Implementations can eliminate this added
            # complexity by caching nodes (i.e., `(seed, ctrl)`
            # pairs) output by previous calls to `eval_next()`.
            (seed, ctrl, y) = IdpfPoplar.eval_next(seed, ctrl,
                correction_words[current_level], current_level, bit)
        out_share.append(y if agg_id == 0 else vec_neg(y))
    return out_share

# Compute the next node in the IDPF tree along the path determined by
# a candidate prefix. The next node is determined by `bit`, the bit
# of the prefix corresponding to the next level of the tree.
#
# TODO Consider implementing some version of the optimization
# discussed at the end of [BBCGGI21, Appendix C.2]. This could on
# average reduce the number of AES calls by a constant factor.
def eval_next(IdpfPoplar, prev_seed, prev_ctrl,
              correction_word, level, bit):
    (seed_cw, ctrl_cw, w_cw) = correction_word
    (s, t) = IdpfPoplar.extend(prev_seed)
    if prev_ctrl == Field2(1):
        s[0] = xor(s[0], seed_cw)
        s[1] = xor(s[1], seed_cw)
        t[0] = t[0] + ctrl_cw[0]
        t[1] = t[1] + ctrl_cw[1]

    next_ctrl = t[bit]
    (next_seed, y) = IdpfPoplar.convert(level, s[bit])
    if next_ctrl == Field2(1):
        y = vec_add(y, w_cw)
    return (next_seed, next_ctrl, y)
~~~
{: #idpf-poplar-eval title="IDPF-evaluation generation algorithm of IdpfPoplar."}

### Auxiliary Functions {#idpf-poplar-helper-functions}

~~~
def extend(IdpfPoplar, seed):
    dst = VERSION + b' idpf poplar extend'
    prg = IdpfPoplar.Prg(seed, dst)
    s = [
        prg.next(IdpfPoplar.Prg.SEED_SIZE),
        prg.next(IdpfPoplar.Prg.SEED_SIZE),
    ]
    b = OS2IP(prg.next(1))
    t = [Field2(b & 1), Field2((b >> 1) & 1)]
    return (s, t)

def convert(IdpfPoplar, level, seed):
    dst = VERSION + b' idpf poplar convert'
    prg = IdpfPoplar.Prg(seed, dst)
    next_seed = prg.next(IdpfPoplar.Prg.SEED_SIZE)
    Field = IdpfPoplar.current_field(level)
    w = prg.next_vec(Field, IdpfPoplar.VALUE_LEN)
    return (next_seed, w)

def encode_public_share(IdpfPoplar, correction_words):
    encoded = Bytes()
    packed_ctrl = 0
    for (level, (_, ctrl_cw, _)) \
        in enumerate(correction_words):
        packed_ctrl |= ctrl_cw[0].as_unsigned() << (2*level)
        packed_ctrl |= ctrl_cw[1].as_unsigned() << (2*level+1)
    l = floor((2*IdpfPoplar.BITS + 7) / 8)
    encoded += I2OSP(packed_ctrl, l)
    for (level, (seed_cw, _, w_cw)) \
        in enumerate(correction_words):
        Field = IdpfPoplar.current_field(level)
        encoded += seed_cw
        encoded += Field.encode_vec(w_cw)
    return encoded

def decode_public_share(IdpfPoplar, encoded):
    l = floor((2*IdpfPoplar.BITS + 7) / 8)
    encoded_ctrl, encoded = encoded[:l], encoded[l:]
    packed_ctrl = OS2IP(encoded_ctrl)
    correction_words = []
    for level in range(IdpfPoplar.BITS):
        Field = IdpfPoplar.current_field(level)
        ctrl_cw = (Field2(packed_ctrl & 1),
                   Field2((packed_ctrl >> 1) & 1))
        packed_ctrl >>= 2
        l = IdpfPoplar.Prg.SEED_SIZE
        seed_cw, encoded = encoded[:l], encoded[l:]
        l = Field.ENCODED_SIZE * IdpfPoplar.VALUE_LEN
        encoded_w_cw, encoded = encoded[:l], encoded[l:]
        w_cw = Field.decode_vec(encoded_w_cw)
        correction_words.append((seed_cw, ctrl_cw, w_cw))
    if len(encoded) != 0:
        raise ERR_DECODE
    return correction_words
~~~
{: #idpf-poplar-helpers title="Helper functions for IdpfPoplar."}

## Poplar1Aes128 {#poplar1-instantiation}

We refer to Poplar1 instantiated with IdpfPoplar (`VALUE_LEN == 2`)
and PrgAes128 ({{prg-aes128}}) as Poplar1Aes128. This VDAF is suitable
for any positive value of `BITS`. Test vectors can be found in
{{test-vectors}}.

# Security Considerations {#security}

> NOTE: This is a brief outline of the security considerations.  This section
> will be filled out more as the draft matures and security analyses are
> completed.

VDAFs have two essential security goals:

1. Privacy: An attacker that controls the network, the Collector, and a subset
   of Clients and Aggregators learns nothing about the measurements of honest
   Clients beyond what it can deduce from the aggregate result.

1. Robustness: An attacker that controls the network and a subset of Clients
   cannot cause the Collector to compute anything other than the aggregate of
   the measurements of honest Clients.

Note that, to achieve robustness, it is important to ensure that the
verification key distributed to the Aggregators (`verify_key`, see {{sec-vdaf-prepare}}) is
never revealed to the Clients.

It is also possible to consider a stronger form of robustness, where the
attacker also controls a subset of Aggregators (see {{BBCGGI19}}, Section 6.3).
To satisfy this stronger notion of robustness, it is necessary to prevent the
attacker from sharing the verification key with the Clients. It is therefore
RECOMMENDED that the Aggregators generate `verify_key` only after a set of
Client inputs has been collected for verification, and re-generate them for each
such set of inputs.

In order to achieve robustness, the Aggregators MUST ensure that the nonces used
to process the measurements in a batch are all unique.

A VDAF is the core cryptographic primitive of a protocol that achieves
the above privacy and robustness goals. It is not sufficient on its own,
however. The application will need to assure a few security properties,
for example:

* Securely distributing the long-lived parameters.
* Establishing secure channels:
  * Confidential and authentic channels among Aggregators, and between the
    Aggregators and the Collector; and
  * Confidential and Aggregator-authenticated channels between Clients and
    Aggregators.
* Enforcing the non-collusion properties required of the specific VDAF in use.

In such an environment, a VDAF provides the high-level privacy property
described above: The Collector learns only the aggregate measurement, and
nothing about individual measurements aside from what can be inferred from the
aggregate result.  The Aggregators learn neither individual measurements nor the
aggregate result.  The Collector is assured that the aggregate statistic
accurately reflects the inputs as long as the Aggregators correctly executed
their role in the VDAF.

On their own, VDAFs do not mitigate Sybil attacks {{Dou02}}. In this attack, the
adversary observes a subset of input shares transmitted by a Client it is
interested in. It allows the input shares to be processed, but corrupts and
picks bogus inputs for the remaining Clients.  Applications can guard against
these risks by adding additional controls on measurement submission, such as
client authentication and rate limits.

VDAFs do not inherently provide differential privacy {{Dwo06}}.  The VDAF approach
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

Thanks to David Cook, Henry Corrigan-Gibbs, Armando Faz-Hernández, Simon
Friedberger, Tim Geoghegan, Mariana Raykova, Jacob Rothstein, and Christopher
Wood for useful feedback on and contributions to the spec.

# Test Vectors {#test-vectors}
{:numbered="false"}

> NOTE Machine-readable test vectors can be found at
> https://github.com/cfrg/draft-irtf-cfrg-vdaf/tree/main/poc/test_vec.

Test vectors cover the generation of input shares and the conversion of input
shares into output shares. Vectors specify the verification key, measurements,
aggregation parameter, and any parameters needed to construct the VDAF. (For
example, for `Prio3AesSum`, the user specifies the number of bits for
representing each summand.)

Byte strings are encoded in hexadecimal To make the tests deterministic,
`gen_rand()` was replaced with a function that returns the requested number of
`0x01` octets.

## Prio3Aes128Count
{:numbered="false"}

~~~
verify_key: "01010101010101010101010101010101"
upload_0:
  measurement: 1
  nonce: "01010101010101010101010101010101"
  public_share: >-
  input_share_0: >-
    a46091d07a930ace79bb11d1d03596bf4f921f7e70b853cf6b8d4969287dfb504a1d
    ea6b0eb01a5f50ad24225186c104
  input_share_1: >-
    0101010101010101010101010101010101010101010101010101010101010101
  round_0:
    prep_share_0: >-
      cdbbf14ef0c19728578ce1e50411e1e26eb49eea4dadfada9ed3d13c71d846b8
    prep_share_1: >-
      32440eb00f3e68d95b9f6e2e856cf534948881bf63c24d315e4954159611ebb5
    prep_message: >-
  out_share_0:
    - 11844627344580086478
  out_share_1:
    - 6602116724834497844
agg_share_0: >-
  a46091d07a930ace
agg_share_1: >-
  5b9f6e2e856cf534
agg_result: 1
~~~

## Prio3Aes128Sum
{:numbered="false"}

~~~
bits: 8
verify_key: "01010101010101010101010101010101"
upload_0:
  measurement: 100
  nonce: "01010101010101010101010101010101"
  public_share: >-
  input_share_0: >-
    a46091d17a930aaf4d02cff822f817a3d10d4d74d526daf00112da46b9b33deaa222
    0ff24fe104b34007f47c4531dc7471b6832358f5d6859fb3b2112e79ec6eb940251d
    14855b16689ab3cfd9100b568729aadfb5558a3bd0277d3ae7c5d967e3525839f26f
    5cb210e4fb0b0aeb0394ce0791de9c4c07f8840dcdd1ce09bb2179bb11d1d03596be
    4f921f7f70b853ce99c2bd80daf08029b7bb7820b7a7632e3b9200ff98adde77a833
    6469ba7fa61ebf135e7f303568ddf63e39978954c40a3fcfa08412f5f03f61699643
    85f167c68c3ae5205e1c3dd075fc76224bf9407ef3fd54334bec36d453460381ee54
    4027bb520f55394873f5dff846794007cc7d77e903b1474095c61140d1e488a98e00
    f433c22491825191261e982affc44e20756db024e0dcdda9746aba73d2ec9a083953
    4a1d0178802fc0ee9393160b34dca94999c91fa788b8308b15880ea3146aabf38e2f
    a4d715c0be7e183fe7f158f47438eaa5a55406da5be56d724afd86e579bc076c669c
    334c93fb724891e0b72c8737a9f65c2d3d56bae20dce052f43293712a603f8a8b9e8
    bcdafad8420ae14201f9a8b4891e9b60dd418d0f71ee2395b9026cb4978f901765e0
    155b127a4fa95a0e0751b95d9ada245c78df820e4bc7f0c9329a5bbad2ee85688cea
    47336da7a798705b6c465678363574e844d1974f6f369e9ef13e920d383f580aa382
    8b7641a77f352b73134886c58e822040747311a9b094137c5f46d6e9ed05bb17d9c7
    0f01b5491805ac83c447035560b00b8e7049c334fcfa003941fa0e307cf52884e461
    8f794848936bfcd8d7f895781d27b006673a6349bdfa04c8c3506b2b64efff5335f7
    6723bce0f1092571cae3d125dcabbb6da4867963ffd29172ef699ecf010101010101
    0101010101010101010132dd9fa5604fadc81ff1636918a6db69
  input_share_1: >-
    01010101010101010101010101010101010101010101010101010101010101010101
    0101010101010101010101010101646430cb3212da0c23bff5618647609c
  round_0:
    prep_share_0: >-
      ede97ab0d3d2dc256a1f82261078cc06b5a423c5f221e9fa029ba023bc71e70fd1
      9e2db541507b4171409bc06c3ac292646430cb3212da0c23bff5618647609c
    prep_share_1: >-
      1216854f2c2d23be95e07dd9ef8733fb779dce023a0e4f7147b74c75c5fd1723a1
      1b7a116c0a89c6b97471597eb2a83c32dd9fa5604fadc81ff1636918a6db69
    prep_message: >-
      56b9af6e525d77c43c4e96089ee1bbf5
  out_share_0:
    - 231691668211413349799981210015670190003
  out_share_1:
    - 108590698709525113146884563352230576306
agg_share_0: >-
  ae4e3131e0f5bea01ba67704684fbfb3
agg_share_1: >-
  51b1cece1f0a4143e45988fb97b040b2
agg_result: 100
~~~

## Prio3Aes128Histogram
{:numbered="false"}

~~~
buckets: [1, 10, 100]
verify_key: "01010101010101010101010101010101"
upload_0:
  measurement: 50
  nonce: "01010101010101010101010101010101"
  public_share: >-
  input_share_0: >-
    a46091d17a930aaf4d02cff822f817a3d10d4d74d526daf00112da46b9b33deaa222
    0ff24fe104b34007f47c4531dc7471b6832358f5d6859fb3b2112e79ec6e79bb11d1
    d03596be4f921f7f70b853cec138b5a4f1a798810bde46a7265fd6bed9bb8cc8d058
    bb224cc75b17f2ebc7f7b6c7a708b11022329fab97ed7d23309116a6fb53d1d9ff45
    9a67eafcddbd190e69069ef82f361a6d4c9616ec3396776834a7d3d5848409cdd89f
    ec7920a858074db9c2e7adfc4b3397339532f80e327f25f31975e3f5d149ba8c8d5b
    f101488f4882ab2b38ddedc84f814435c2b227ffeee7affc5076d78819d7ce68f247
    355af67c52fc7ef9bbcbf8bc910af7c047a28dfeb4f92158934ce93dac747c1b55a8
    f5efb18e944e0579602c918e670f8d543b530d8ba3730d0a43e8bcd2d54f736c4db1
    ac64c9c49dc5ab20c0ac0cf6530b01010101010101010101010101010101d451ca17
    ca18344ac4925510c71e5ac8
  input_share_1: >-
    01010101010101010101010101010101010101010101010101010101010101010101
    0101010101010101010101010101ef377f05b86ffa85ed011213230bb1d5
  round_0:
    prep_share_0: >-
      a1a7093768a9f8a3c01e31f7e9c6dc7925407d03831c510799fcf30a03c61bcd35
      78329d502e06cd01e994c227d3d1afef377f05b86ffa85ed011213230bb1d5
    prep_share_1: >-
      5e58f6c8975607403fe1ce081639238809c0227ef8c371e897e7950d763d8a37f7
      ee6acb826a97f3ef37fd59e6a95511d451ca17ca18344ac4925510c71e5ac8
    prep_message: >-
      3b66b5127277cecf29934703e415eb1d
  out_share_0:
    - 218494809353158975333103031759951894435
    - 277877721980181983205633439801202130410
    - 215511796844427285058159435311010143348
    - 151150421348124479376036084370309246062
  out_share_1:
    - 121787557567779487613762741607948871774
    - 62404644940756479741232333566698635799
    - 124770570076511177888706338056890622862
    - 189131945572813983570829688997591520147
agg_share_0: >-
  a46091d17a930aaf4d02cff822f817a3d10d4d74d526daf00112da46b9b33deaa2220f
  f24fe104b34007f47c4531dc7471b6832358f5d6859fb3b2112e79ec6e
agg_share_1: >-
  5b9f6e2e856cf534b2fd3007dd07e85e2ef2b28b2ad924f3feed25b9464cc2175dddf0
  0db01efb30bff80b83bace238e8e497cdca70a295e604c4deed1861393
agg_result: [0, 0, 1, 0]
~~~

## Poplar1Aes128
{:numbered="false"}

### Sharding
{:numbered="false"}

~~~
bits: 4
upload_0:
  measurement: 13
  nonce: "01010101010101010101010101010101"
  public_share: >-
    9a00000000000000000000000000000000ffffffff00000000bd5fef66a8181fb000
    000000000000000000000000000000ffffffff00000000dbf324f2b4351711000000
    00000000000000000000000000ffffffff00000000984542b43f4008f40000000000
    00000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000113aec130616497e38eaafb95841bad26f773979c71d5422d1c
    875c6c007575ce
  input_share_0: >-
    01010101010101010101010101010101010101010101010101010101010101011926
    0bd7b833c3b313d7ba6d15a9f16fec202c82ddf2848909acc634a461a6b8b7758b10
    e0adb885083645e2bbe0c575137f41a015e6cc2ce8fed760ca08589f957eef3d1667
    07d9044d22411142e73568bba4e2f7150dab3316e30966a1d73f660ec47316af0198
    e8682372a232bcef
  input_share_1: >-
    01010101010101010101010101010101010101010101010101010101010101013422
    59973b9807dbbb662f6a81067220a977e09ad54ba5048edb2118c95bb8f3ce11a0dd
    6f0bda66dc2dc274f26ec69e091747a0b26b57ad629d905fae98204c5171179db567
    12e5dd66f792eddc6da955476f1471eb5c12aac55b35c1d80a2022d30da1ac00dfc5
    8c581e8304ab59f1
~~~

### Preparation, Aggregation, and Unsharding
{:numbered="false"}

~~~
verify_key: "01010101010101010101010101010101"
agg_param: (0, [0, 1])
upload_0:
  round_0:
    prep_share_0: >-
      48c3581799a109398b1943c10957b8c2536f292900de6436
    prep_share_1: >-
      8377f3fcd4d2d1f33233948d19fe2c385f97c52d8e007f76
    prep_message: >-
      cc3b4c146e73db2cbd4cd84e2355e4fab306ee568edee3ac
  round_1:
    prep_share_0: >-
      64ce1f88d77b2a65
    prep_share_1: >-
      9b31e0762884d59c
    prep_message: >-
  out_share_0:
    - 18352387916526274078
    - 14559030685141423577
  out_share_1:
    - 94356152888310243
    - 3887713384273160745
agg_share_0: >-
  feb0c79330b8461eca0c114565ddd5d9
agg_share_1: >-
  014f386bcf47b9e335f3eeb99a222a29
agg_result: [0, 1]
~~~

~~~
verify_key: "01010101010101010101010101010101"
agg_param: (1, [0, 1, 2, 3])
upload_0:
  round_0:
    prep_share_0: >-
      37c72ca578a032eaeffbd9e63d29e6eaa205d9d67628d055
    prep_share_1: >-
      ab956611d15cfcef0773a4e435fdcb83909785aa50c17513
    prep_message: >-
      e35c92b749fd2fd9f76f7eca7327b26d329d5f81c6ea4567
  round_1:
    prep_share_0: >-
      ee63dfb515814411
    prep_share_1: >-
      119c2049ea7ebbf0
    prep_message: >-
  out_share_0:
    - 7623875273889432259
    - 4753532626118505607
    - 9999595461072379379
    - 1320535832873937471
  out_share_1:
    - 10822868795525152062
    - 13693211443296078714
    - 8447148608342204942
    - 17126208236540646851
agg_share_0: >-
  69cd722b281042c341f7f0bcf805f4878ac5b3177ad3ddf312537c57efa02a3f
agg_share_1: >-
  96328dd3d7efbd3ebe080f4207fa0b7a753a4ce7852c220eedac83a7105fd5c3
agg_result: [0, 0, 0, 1]
~~~

~~~
verify_key: "01010101010101010101010101010101"
agg_param: (2, [0, 2, 4, 6])
upload_0:
  round_0:
    prep_share_0: >-
      7eb8dbda5ea6807e53f22d3f74a43f59ed83ef578b070654
    prep_share_1: >-
      567632dc63ec2294c6f030077726f87ec11e2fc53a38f640
    prep_message: >-
      d52f0eb6c292a3121ae25d47ebcb37d6aea21f1dc53ffc93
  round_1:
    prep_share_0: >-
      9e92c793980229fd
    prep_share_1: >-
      616d386b67fdd604
    prep_message: >-
  out_share_0:
    - 1646250657834468215
    - 16923505979406688621
    - 18330814903122515861
    - 12155602082232726549
  out_share_1:
    - 16800493411580116106
    - 1523238090007895700
    - 115929166292068460
    - 6291141987181857773
agg_share_0: >-
  16d8a840477a0377eadc5f0610bc216dfe642308980dd795a8b15fb0ce7af415
agg_share_1: >-
  e92757beb885fc8a1523a0f8ef43de94019bdcf667f2286c574ea04e31850bed
agg_result: [0, 0, 0, 1]
~~~

~~~
verify_key: "01010101010101010101010101010101"
agg_param: (3, [1, 3, 5, 7, 9, 13, 15])
upload_0:
  round_0:
    prep_share_0: >-
      246777985de3e9fd0ea9e8ea429ae3c7255c0b2aa84cff6bd5c0079a122be38b53
      4e75cbfe8abb2c54b5b277089bb2708b274a17ce26df0ea9881487ac852eee30c1
      8ba6dc40beb7f33e5003fdf065eec844e320d0b9ff49b0b29f5bbbcbcc8d
    prep_share_1: >-
      3dea0b9e72389ea0d62521e91214c654ebf9b2a3d855a32219755216f4cb8eca0d
      864838efc99f1a5d2adecf87e4ff0b839fb7191d4c58c5fd6753c0c6a2fb155071
      efff9719f0e9645d70b398ca24ecb2fa8fbb56a6a90ce6d95b675e1e28f2
    prep_message: >-
      62518336d01c889de4cf0ad354afaa1c1155bdce80a2a28def3559b106f7725560
      d4be04ee545a46b1e091469080b17c0ec70130eb7337d4a6ef684873282a030133
      7ba6735aafa1579bc0b796ba8adb7b3f72dc2760a856978bfac319e9f592
  round_1:
    prep_share_0: >-
      40521213baba54c83b4ddc0cb1e3e4c16897bb8831cc12ea91a82927dd30ae58
    prep_share_1: >-
      3fadedec4545ab37c4b223f34e1c1b3e97684477ce33ed156e57d6d822cf5195
    prep_message: >-
  out_share_0:
    - 27022242238524926041754024638978288940369802983157338113702795433392718442891
    - 8433446103891669428510589487794410319530091467635619512122120272876905203470
    - 31927171851194534364500488903327032909992419490289770138187660233081601268509
    - 13674389066590417186009193737398514883303633790292716630453797389670854762435
    - 49245655988555337792760994399532100867010365510706353464574012401106060986059
    - 38418164104898327452350816690091778787588836972103923142413897241001677348897
    - 17473652484574293745985786122460988541722879368489070298827855759184581179349
  out_share_1:
    - 30873802380133171670031467865365664986265189349662943906025996570563846377058
    - 49462598514766428283274903016549543607104900865184662507606671731079659616479
    - 25968872767463563347285003601016921016642572842530511881541131770874963551440
    - 44221655552067680525776298766945439043331358542527565389274994614285710057514
    - 8650388630102759919024498104811853059624626822113928555154779602850503833890
    - 19477880513759770259434675814252175139046155360716358877314894762954887471053
    - 40422392134083803965799706381882965384912112964331211720900936244771983640600
agg_share_0: >-
  3bbe0c0f2a3ecf406419e5a8636f13c1102df2df86b4dec82daa4669b24f718b12a529
  4d99b7a604a6944dbe1b81cfcc98e4a5a1fa0d08ac727f620ee0b4870e4696238e0b88
  71bb6d93ab6c8fc1680da244dfc59bd0b6f70b8dae1f4c1a1b1d1e3b6e1053afb851cc
  ae5d9ddabb8bff59afea5f6f905e0b2dd1b8a9cc911fc36ce00db4dfb57d404c6bddc9
  0a93a35fa5a476634aab5c2c46b467e2a6ce46cb54efe909f5c78891ac58d782afb5a4
  4dbc5b2f0c190d4ebe8ca7eb1e4af8e02126a1bca0b523a4c67c7176bebb04afed7b50
  6fc5c343e3e7727d3027d68937d5
agg_share_1: >-
  4441f3f0d5c130bf9be61a579c90ec3eefd20d20794b2137d255b9964db08e626d5ad6
  b2664859fb596bb241e47e3033671b5a5e05f2f7538d809df11f4b78df3969dc71f477
  8e44926c5493703e97f25dbb203a642f4908f47251e0b3e5e4d061c491efac5047ae33
  51a26225447400a65015a0906fa1f4d22e4756336ee02a131ff24b204a82bfb3942236
  f56c5ca05a5b899cb554a3d3b94b981d5931b9222b1016f60a38776e53a7287d504a5b
  b243a4d0f3e6f2b141735814e1b5071fcd595e435f4adc5b39838e894144fb501284af
  903a3cbc1c188d82cfd82976c818
agg_result: [0, 0, 0, 0, 0, 1, 0]
~~~
