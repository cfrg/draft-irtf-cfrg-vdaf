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
    name: David Cook
    organization: ISRG
    email: divergentdave@gmail.com
 -
    name: Christopher Patton
    organization: Cloudflare
    email: chrispatton+ietf@gmail.com
 -
    name: Phillipp Schoppmann
    organization: Google
    email: schoppmann@google.com

normative:

  SP800-185:
    title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash"
    date: December 2016
    seriesinfo: NIST Special Publication 800-185

  FIPS202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    date: August 2015
    seriesinfo: NIST FIPS PUB 202

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

  DPRS23:
    title: "Verifiable Distributed Aggregation Functions"
    author:
      - ins: H. Davis
      - ins: C. Patton
      - ins: M. Rosulek
      - ins: P. Schoppmann
    target: https://ia.cr/2023/130

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

  GKWWY20:
    title: Better concrete security for half-gates garbling (in the multi-instance setting)
    authors:
      - ins: C. Guo
      - ins: J. Katz
      - ins: X. Wang
      - ins: C. Weng
      - ins: Y. Yu
    date: 2020
    seriesinfo: CRYPTO 2020
    target: https://link.springer.com/chapter/10.1007/978-3-030-56880-1_28

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
multi-party computation (MPC): No participant in the protocol should learn
anything about an individual input beyond what it can deduce from the aggregate.
In this document, we describe Verifiable Distributed Aggregation Functions
(VDAFs) as a general class of protocols that achieve this goal.

VDAF schemes achieve their privacy goal by distributing the computation of the
aggregate among a number of non-colluding aggregation servers. As long as a
subset of the servers executes the protocol honestly, VDAFs guarantee that no
input is ever accessible to any party besides the client that submitted it. At
the same time, VDAFs are "verifiable" in the sense that malformed inputs that
would otherwise garble the output of the computation can be detected and removed
from the set of input measurements. We refer to this property as "robustness".

In addition to these MPC-style security goals of privacy and robustness, VDAFs
can be composed with various mechanisms for differential privacy, thereby
providing the added assurance that the aggregate result itself does not leak
too much information about any one measurement.

> TODO(issue #94) Provide guidance for local and central DP and point to it
> here.

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
protocols vary in their operational and security requirements, sometimes in
subtle but consequential ways. This document therefore has two important goals:

 1. Providing higher-level protocols like {{?DAP=I-D.draft-ietf-ppm-dap}} with
    a simple, uniform interface for accessing privacy-preserving measurement
    schemes, documenting relevant operational and security requirements, and
    specifying constraints for safe usage:

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

(\*) Indicates a change that breaks wire compatibility with the previous draft.

05:

* IdpfPoplar: Replace PrgSha3 with PrgFixedKeyAes128, a fixed-key mode for
  AES-128 based on a construction from {{GKWWY20}}. This change is intended to
  improve performance of IDPF evaluation. Note that the new PRG is not suitable
  for all applications. (\*)

* Idpf: Add a binder string to the key-generation and evaluation algorithms.
  This is used to plumb the nonce generated by the Client to the PRG.

* Plumb random coins through the interface of randomized algorithms.
  Specifically, add a random input to (V)DAF sharding algorithm and IDPF
  key-generation algorithm and require implementations to specify the length of
  the random input. Accordingly, update Prio3, Poplar1, and IdpfPoplar to match
  the new interface. This change is intended to improve coverage of test
  vectors.

* Use little-endian byte-order for field element encoding. (\*)

* Poplar1: Move the last step of sketch evaluation from `prep_next()` to
  `prep_shares_to_prep()`.

04:

* Align security considerations with the security analysis of {{DPRS23}}.

* Vdaf: Pass the nonce to the sharding algorithm.

* Vdaf: Rather than allow the application to choose the nonce length, have each
  implementation of the Vdaf interface specify the expected nonce length. (\*)

* Prg: Split "info string" into two components: the "customization string",
  intended for domain separation; and the "binder string", used to bind the
  output to ephemeral values, like the nonce, associated with execution of a
  (V)DAF.

* Replace PrgAes128 with PrgSha3, an implementation of the Prg interface based
  on SHA-3, and use the new scheme as the default. Accordingly, replace
  Prio3Aes128Count with Prio3Count, Poplar1Aes128 with Poplar1, and so on. SHA-3
  is a safer choice for instantiating a random oracle, which is used in the
  analysis of Prio3 of {{DPRS23}}. (\*)

* Prio3, Poplar1: Ensure each invocation of the Prg uses a distinct
  customization string, as suggested by {{DPRS23}}. This is intended to make
  domain separation clearer, thereby simplifying security analysis. (\*)

* Prio3: Replace "joint randomness hints" sent in each input share with "joint
  randomness parts" sent in the public share. This reduces communication
  overhead when the number of shares exceeds two. (\*)

* Prio3: Bind nonce to joint randomness parts. This is intended to address
  birthday attacks on robustness pointed out by {{DPRS23}}. (\*)

* Poplar1: Use different Prg invocations for producing the correlated randomness
  for inner and leaf nodes of the IDPF tree. This is intended to simplify
  implementations. (\*)

* Poplar1: Don't bind the candidate prefixes to the verifier randomness. This is
  intended to improve performance, while not impacting security. According to
  the analysis of {{DPRS23}}, it is necessary to restrict Poplar1 usage such
  that no report is aggregated more than once at a given level of the IDPF tree;
  otherwise, attacks on privacy may be possible. In light of this restriction,
  there is no added benefit of binding to the prefixes themselves. (\*)

* Poplar1: During preparation, assert that all candidate prefixes are unique
  and appear in order. Uniqueness is required to avoid erroneously rejecting a
  valid report; the ordering constraint ensures the uniqueness check can be
  performed efficiently. (\*)

* Poplar1: Increase the maximum candidate prefix count in the encoding of the
  aggregation parameter. (\*)

* Poplar1: Bind the nonce to the correlated randomness derivation. This is
  intended to provide defense-in-depth by ensuring the Aggregators reject the
  report if the nonce does not match what the Client used for sharding. (\*)

* Poplar1: Clarify that the aggregation parameter encoding is OPTIONAL.
  Accordingly, update implementation considerations around cross-aggregation
  state.

* IdpfPoplar: Add implementation considerations around branching on the values
  of control bits.

* IdpfPoplar: When decoding the the control bits in the public share, assert
  that the trailing bits of the final byte are all zero. (\*)

03:

* Define codepoints for (V)DAFs and use them for domain separation in Prio3 and
  Poplar1. (\*)

* Prio3: Align joint randomness computation with revised paper {{BBCGGI19}}.
  This change mitigates an attack on robustness. (\*)

* Prio3: Remove an intermediate PRG evaluation from query randomness generation.
  (\*)

* Add additional guidance for choosing FFT-friendly fields.

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

* Field: Require that field elements are fully reduced before decoding. (\*)

* Define new field Field255.

01:

* Require that VDAFs specify serialization of aggregate shares.

* Define Distributed Aggregation Functions (DAFs).

* Prio3: Move proof verifier check from `prep_next()` to
  `prep_shares_to_prep()`. (\*)

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

A global constant `VERSION` of type `Unsigned` is defined, which algorithms are
free to use as desired. Its value SHALL be `5`.

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

* `concat(parts: Vec[Bytes]) -> Bytes` returns the concatenation of the input
  byte strings, i.e., `parts[0] || ... || parts[len(parts)-1]`.

* `front(length: Unsigned, vec: Vec[Any]) -> (Vec[Any], Vec[Any])` splits `vec`
  into two vectors, where the first vector is made up of the first `length`
  elements of the input. I.e., `(vec[:length], vec[length:])`.

* `xor(left: Bytes, right: Bytes) -> Bytes` returns the bitwise XOR of `left`
  and `right`. An exception is raised if the inputs are not the same length.

* `to_be_bytes(val: Unsigned, length: Unsigned) -> Bytes` converts `val` to
  big-endian bytes; its value MUST be in range `[0, 2^(8*length))`. Function
  `from_be_bytes(encoded: Bytes) -> Unsigned` computes the inverse.

* `to_le_bytes(val: Unsigned, length: Unsigned) -> Bytes` converts `val` to
  little-endian bytes; its value MUST be in range `[0, 2^(8*length))`. Function
  `from_le_bytes(encoded: Bytes) -> Unsigned` computes the inverse.

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
  "input shares" and sends one input share to each Aggregator. We sometimes
  refer to this sequence of input shares collectively as the Client's "report".
* The Aggregators convert their input shares into "output shares".
    * Output shares are in one-to-one correspondence with the input shares.
    * Just as each Aggregator receives one input share of each measurement, if
      this process succeeds, then each aggregator holds one output share.
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

| Parameter     | Description                                                    |
|:--------------|:---------------------------------------------------------------|
| `ID`          | Algorithm identifier for this DAF. A 32-bit, unsigned integer. |
| `SHARES`      | Number of input shares into which each measurement is sharded. |
| `RAND_SIZE`   | Size of the random byte string passed to sharding algorithm.   |
| `Measurement` | Type of each measurement.                                      |
| `AggParam`    | Type of aggregation parameter.                                 |
| `OutShare`    | Type of each output share.                                     |
| `AggResult`   | Type of the aggregate result.                                  |
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

Each DAF is identified by a unique, 32-bit integer `ID`. Identifiers for each
(V)DAF specified in this document are defined in {{codepoints}}.

## Sharding {#sec-daf-shard}

In order to protect the privacy of its measurements, a DAF Client shards its
measurements into a sequence of input shares. The `measurement_to_input_shares`
method is used for this purpose.

* `Daf.measurement_to_input_shares(input: Measurement, rand:
  Bytes[Daf.RAND_SIZE]) -> tuple[Bytes, Vec[Bytes]]` is the randomized sharding
  algorithm run by each Client. The input `rand` consists of the random bytes
  consumed by the algorithm. This value MUST be generated using a
  cryptographically secure pseudorandom number generator (CSPRNG). It consumes
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
      |              |              |     |
      |              |         ...  |    public_share
      |              |              |     |
      |    +---------|-----+--------|-----+
      |    |         |     |        |     |
      V    |         V     |        V     |
     input_share_0  input_share_1  input_share_[SHARES-1]
      |    |         |     |   ...  |     |
      V    V         V     V        V     V
    Aggregator 0   Aggregator 1    Aggregator SHARES-1
~~~~
{: #shard-flow title="The Client divides its measurement into input shares and distributes them to the Aggregators. The public share is broadcast to all Aggregators."}

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

## Validity of Aggregation Parameters {#sec-daf-validity-scopes}

Concrete DAFs implementations MAY impose certain restrictions for input shares
and aggregation parameters. Protocols using a DAF MUST ensure that for each
input share and aggregation parameter `agg_param`, `Daf.prep` is only called if
`Daf.is_valid(agg_param, previous_agg_params)` returns True, where
`previous_agg_params` contains all aggregation parameters that have previously
been used with the same input share.

DAFs MUST implement the following function:

* `Daf.is_valid(agg_param: AggParam, previous_agg_params: Vec[AggParam]) ->
  Bool`: Checks if the `agg_param` is compatible with all elements of
  `previous_agg_params`.

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

Implementation note: For most natural DAFs (and VDAFs) it is not necessary for
an Aggregator to store all output shares individually before aggregating.
Typically it is possible to merge output shares into aggregate shares as they
arrive, merge these into other aggregate shares, and so on. In particular, this
is the case when the output shares are vectors over some finite field and
aggregating them involves merely adding up the vectors element-wise. Such is the
case for Prio3 {{prio3}} and Poplar1 {{poplar1}}.

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
        rand = gen_rand(Daf.RAND_SIZE)
        (public_share, input_shares) = \
            Daf.measurement_to_input_shares(measurement, rand)

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
| `ID`              | Algorithm identifier for this VDAF |
| `VERIFY_KEY_SIZE` | Size (in bytes) of the verification key ({{sec-vdaf-prepare}}) |
| `RAND_SIZE`       | Size of the random byte string passed to sharding algorithm |
| `NONCE_SIZE`      | Size (in bytes) of the nonce |
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

Each VDAF is identified by a unique, 32-bit integer `ID`. Identifiers for each
(V)DAF specified in this document are defined in {{codepoints}}. The following
method is defined for every VDAF:

~~~
def custom(Vdaf, usage: Unsigned) -> Bytes:
    return format_custom(0, Vdaf.ID, usage)
~~~

It is used to construct a customization string for an instance of `Prg` used by
the VDAF. (See {{prg}}.)

## Sharding {#sec-vdaf-shard}

Sharding transforms a measurement into input shares as it does in DAFs
(cf. {{sec-daf-shard}}); in addition, it takes a nonce as input and
produces a public share:

* `Vdaf.measurement_to_input_shares(measurement: Measurement, nonce:
  Bytes[Vdaf.NONCE_SIZE], rand: Bytes[Vdaf.RAND_SIZE]) -> tuple[Bytes,
  Vec[Bytes]]` is the randomized sharding algorithm run by each Client. Input
  `rand` consists of the random bytes consumed by the algorithm. It consumes
  the measurement and the nonce and produces a public share, distributed to each
  of Aggregators, and the corresponding sequence of input shares, one for each
  Aggregator. Depending on the VDAF, the input shares may encode additional
  information used to verify the recovered output shares (e.g., the "proof
  shares" in Prio3 {{prio3}}). The length of the output vector MUST be `SHARES`.

In order to ensure privacy of the measurement, the Client MUST generate the
random bytes and nonce using a CSPRNG. (See {{security}} for details.)

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

* `Vdaf.prep_init(verify_key: Bytes[Vdaf.VERIFY_KEY_SIZE], agg_id: Unsigned,
  agg_param: AggParam, nonce: Bytes[Vdaf.NONCE_SIZE], public_share: Bytes,
  input_share: Bytes) -> Prep` is the deterministic preparation-state
  initialization algorithm run by each Aggregator to begin processing its input
  share into an output share. Its inputs are the shared verification key
  (`verify_key`), the Aggregator's unique identifier (`agg_id`), the aggregation
  parameter (`agg_param`), the nonce provided by the environment (`nonce`, see
  {{run-vdaf}}), the public share (`public_share`), and one of the input
  shares generated by the client (`input_share`). Its output is the Aggregator's
  initial preparation state.

  It is up to the high level protocol in which the VDAF is used to arrange for
  the distribution of the verification key prior to generating and processing
  reports. (See {{security}} for details.)

  Protocols using the VDAF MUST ensure that the Aggregator's identifier is equal
  to the integer in range `[0, SHARES)` that matches the index of `input_share`
  in the sequence of input shares output by the Client.

  Protocols MUST ensure that public share consumed by each of the Aggregators is
  identical. This is security critical for VDAFs such as Poplar1.

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

## Validity of Aggregation Parameters {#sec-vdaf-validity-scopes}

Similar to DAFs (see {{sec-daf-validity-scopes}}), VDAFs MAY impose
restrictions for input shares and aggregation parameters. Protocols using a VDAF
MUST ensure that for each input share and aggregation parameter `agg_param`, the
preparation phase (including `Vdaf.prep_init`, `Vdaf.prep_next`, and
`Vdaf.prep_shares_to_prep`; see {{sec-vdaf-prepare}}) is only called if
`Vdaf.is_valid(agg_param, previous_agg_params)` returns True, where
`previous_agg_params` contains all aggregation parameters that have previously
been used with the same input share.

VDAFs MUST implement the following function:

* `Vdaf.is_valid(agg_param: AggParam, previous_agg_params: Vec[AggParam]) ->
  Bool`: Checks if the `agg_param` is compatible with all elements of
  `previous_agg_params`.

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
             verify_key: Bytes[Vdaf.VERIFY_KEY_SIZE],
             agg_param: Vdaf.AggParam,
             nonces: Vec[Bytes[Vdaf.NONCE_SIZE]],
             measurements: Vec[Vdaf.Measurement]):
    out_shares = []
    for (nonce, measurement) in zip(nonces, measurements):
        # Each Client shards its measurement into input shares.
        rand = gen_rand(Vdaf.RAND_SIZE)
        (public_share, input_shares) = \
            Vdaf.measurement_to_input_shares(measurement, nonce, rand)

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
        encoded += to_le_bytes(x.as_unsigned(), Field.ENCODED_SIZE)
    return encoded

def decode_vec(Field, encoded: Bytes) -> Vec[Field]:
    L = Field.ENCODED_SIZE
    if len(encoded) % L != 0:
        raise ERR_DECODE

    vec = []
    for i in range(0, len(encoded), L):
        encoded_x = encoded[i:i+L]
        x = from_le_bytes(encoded_x)
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
def vec_sub(left: Vec[Field], right: Vec[Field]):
    """
    Subtract the right operand from the left and return the result.
    """
    return list(map(lambda x: x[0] - x[1], zip(left, right)))

def vec_add(left: Vec[Field], right: Vec[Field]):
    """Add the right operand to the left and return the result."""
    return list(map(lambda x: x[0] + x[1], zip(left, right)))
~~~
{: #field-helper-functions title="Common functions for finite fields."}

### FFT-Friendly Fields {#field-fft-friendly}

Some VDAFs require fields that are suitable for efficient computation of the
discrete Fourier transform, as this allows for fast polynomial interpolation.
(One example is Prio3 ({{prio3}}) when instantiated with the generic FLP of
{{flp-generic-construction}}.) Specifically, a field is said to be
"FFT-friendly" if, in addition to satisfying the interface described in
{{field}}, it implements the following method:

* `Field.gen() -> Field` returns the generator of a large subgroup of the
  multiplicative group. To be FFT-friendly, the order of this subgroup MUST be a
  power of 2. In addition, the size of the subgroup dictates how large
  interpolated polynomials can be. It is RECOMMENDED that a generator is chosen
  with order at least `2^20`.

FFT-friendly fields also define the following parameter:

* `GEN_ORDER: Unsigned` is the order of a multiplicative subgroup generated by
  `Field.gen()`.

### Parameters

The tables below define finite fields used in the remainder of this document.

| Parameter    | Field64               | Field128                       | Field255   |
|:-------------|:----------------------|:-------------------------------|:-----------|
| MODULUS      | 2^32 * 4294967295 + 1 | 2^66 * 4611686018427387897 + 1 | 2^255 - 19 |
| ENCODED_SIZE | 8                     | 16                             | 32         |
| Generator    | 7^4294967295          | 7^4611686018427387897          | n/a        |
| GEN_ORDER    | 2^32                  | 2^66                           | n/a        |
{: #fields title="Parameters for the finite fields used in this document."}

## Pseudorandom Generators {#prg}

A pseudorandom generator (PRG) is used to expand a short, (pseudo)random seed
into a long string of pseudorandom bits. A PRG suitable for this document
implements the interface specified in this section.

PRGs are defined by a class `Prg` with the following associated parameter:

* `SEED_SIZE: Unsigned` is the size (in bytes) of a seed.

A concrete `Prg` implements the following class method:

* `Prg(seed: Bytes[Prg.SEED_SIZE], custom: Bytes, binder: Bytes)` constructs an
  instance of `Prg` from the given seed and customization and binder strings.
  (See below for definitions of these.) The seed MUST be of length `SEED_SIZE`
  and MUST be generated securely (i.e., it is either the output of `gen_rand` or
  a previous invocation of the PRG).

* `prg.next(length: Unsigned)` returns the next `length` bytes of output of PRG.
  If the seed was securely generated, the output can be treated as pseudorandom.

Each `Prg` has two derived class methods. The first is used to derive a fresh
seed from an existing one. The second is used to compute a sequence of
pseudorandom field elements. For each method, the seed MUST be of length
`SEED_SIZE` and MUST be generated securely (i.e., it is either the output of
`gen_rand` or a previous invocation of the PRG).

~~~
def derive_seed(Prg,
                seed: Bytes[Prg.SEED_SIZE],
                custom: Bytes,
                binder: Bytes):
    """Derive a new seed."""
    prg = Prg(seed, custom, binder)
    return prg.next(Prg.SEED_SIZE)

def next_vec(self, Field, length: Unsigned):
    """Output the next `length` pseudorandom elements of `Field`."""
    m = next_power_of_2(Field.MODULUS) - 1
    vec = []
    while len(vec) < length:
        x = from_le_bytes(self.next(Field.ENCODED_SIZE))
        x &= m
        if x < Field.MODULUS:
            vec.append(Field(x))
    return vec

def expand_into_vec(Prg,
                    Field,
                    seed: Bytes[Prg.SEED_SIZE],
                    custom: Bytes,
                    binder: Bytes,
                    length: Unsigned):
    """
    Expand the input `seed` into vector of `length` field elements.
    """
    prg = Prg(seed, custom, binder)
    return prg.next_vec(Field, length)
~~~
{: #prg-derived-methods title="Derived class methods for PRGs."}

### PrgSha3 {#prg-sha3}

This section describes PrgSha3, a PRG based on the Keccak permutation of SHA-3
{{FIPS202}}. Keccak is used in the cSHAKE128 mode of operation {{SP800-185}}.
This Prg is RECOMMENDED for all use cases within VDAFs.

~~~
class PrgSha3(Prg):
    """PRG based on SHA-3 (cSHAKE128)."""

    # Associated parameters
    SEED_SIZE = 16

    def __init__(self, seed, custom, binder):
        self.l = 0
        self.x = seed + binder
        self.s = custom

    def next(self, length: Unsigned) -> Bytes:
        self.l += length

        # Function `cSHAKE128(x, l, n, s)` is as defined in
        # [SP800-185, Section 3.3].
        #
        # Implementation note: Rather than re-generate the output
        # stream each time `next()` is invoked, most implementations
        # of SHA-3 will expose an "absorb-then-squeeze" API that
        # allows stateful handling of the stream.
        stream = cSHAKE128(self.x, self.l, b'', self.s)
        return stream[-length:]
~~~
{: title="Definition of PRG PrgSha3."}

### PrgFixedKeyAes128 {#prg-fixed-key-aes128}

While PrgSha3 as described above can be securely used in all cases where a Prg
is needed in the VDAFs described in this document, there are some cases where
a more efficient instantiation based on fixed-key AES is possible. For now, this
is limited to the Prg used inside the Idpf {{idpf}} implementation in Poplar1
{{idpf-poplar}}. It is NOT RECOMMENDED to use this Prg anywhere else.
See Security Considerations {{security}} for a more detailed discussion.

~~~
class PrgFixedKeyAes128(Prg):
    """
    PRG based on a circular collision-resistant hash function from
    fixed-key AES.
    """

    # Associated parameters
    SEED_SIZE = 16

    def __init__(self, seed, custom, binder):
        self.length_consumed = 0

        # Use SHA-3 to derive a key from the binder and customization
        # strings. Note that the AES key does not need to be kept
        # secret from any party. However, when used with IdpfPoplar,
        # we require the binder to be a random nonce.
        #
        # Implementation note: This step can be cached across PRG
        # evaluations with many different seeds.
        self.fixed_key = cSHAKE128(binder, 16, b'', custom)
        self.seed = seed

    def next(self, length: Unsigned) -> Bytes:
        offset = self.length_consumed % 16
        new_length = self.length_consumed + length
        block_range = range(
            int(self.length_consumed / 16),
            int(new_length / 16) + 1)
        self.length_consumed = new_length

        hashed_blocks = [
            self.hash_block(xor(self.seed, to_le_bytes(i, 16))) \
                         for i in block_range
        ]
        return concat(hashed_blocks)[offset:offset+length]

    def hash_block(self, block):
        """
        The multi-instance tweakable circular correlation-robust hash
        function of [GKWWY20] (Section 4.2). The tweak here is the key
        that stays constant for all PRG evaluations of the same client,
        but differs between clients.

        Function `AES128(key, block)` is the AES-128 blockcipher.
        """
        lo, hi = block[:8], block[8:]
        sigma_block = concat([hi, xor(hi, lo)])
        return xor(AES128(self.fixed_key, sigma_block), sigma_block)
~~~

### The Customization and Binder Strings

PRGs are used to map a seed to a finite domain, e.g., a fresh seed or a vector
of field elements. To ensure domain separation, the derivation is needs to be
bound to some distinguished "customization string". The customization string
encodes the following values:

1. The document version (i.e.,`VERSION`);
1. The "class" of the algorithm using the output (e.g., VDAF);
1. A unique identifier for the algorithm; and
1. Some indication of how the output is used (e.g., for deriving the measurement
   shares in Prio3 {{prio3}}).

The following algorithm is used in the remainder of this document in order to
format the customization string:

~~~
def format_custom(algo_class: Unsigned,
                  algo: Unsigned,
                  usage: Unsigned) -> Bytes:
    return concat([
        to_be_bytes(VERSION, 1),
        to_be_bytes(algo_class, 1),
        to_be_bytes(algo, 4),
        to_be_bytes(usage, 2),
    ])
~~~

It is also sometimes necessary to bind the output to some ephemeral value that
multiple parties need to agree on. We call this input the "binder string".

# Prio3 {#prio3}

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
each Aggregator sums up its shares locally. Finally, the Collector sums up the
aggregate shares and computes the aggregate result.

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
share of the verifier message. Furthermore, the privacy property of the FLP
system ensures that the verifier message reveals nothing about the input's
validity. Therefore, to decide if an input is valid, the Aggregators will run
the query-generation algorithm locally, exchange verifier shares, combine them
to recover the verifier message, and run the decision algorithm.

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

    # Shard the input and the proof.
    input_shares = linear_secret_share(inp, num_shares, Flp.Field)
    proof_shares = linear_secret_share(proof, num_shares, Flp.Field)

    # Verifier queries the input shares and proof shares.
    verifier_shares = [
        Flp.query(
            input_share,
            proof_share,
            query_rand,
            joint_rand,
            num_shares,
        )
        for input_share, proof_share in zip(input_shares, proof_shares)
    ]

    # Combine the verifier shares into the verifier.
    verifier = Flp.Field.zeros(len(verifier_shares[0]))
    for verifier_share in verifier_shares:
        verifier = vec_add(verifier, verifier_share)

    # Verifier decides if the input is valid.
    return Flp.decide(verifier)
~~~
{: #run-flp title="Execution of an FLP."}

The proof system is constructed so that, if `inp` is a valid input, then
`run_flp(Flp, inp, 1)` always returns `True`. On the other hand, if `inp` is
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

For some FLPs, the encoded input also includes redundant field elements that
are useful for checking the proof, but which are not needed after the proof has
been checked. An example is the "integer sum" data type from {{CGB17}} in which
an integer in range `[0, 2^k)` is encoded as a vector of `k` field elements,
each representing a bit of the integer (this type is also defined in
{{prio3sum}}). After consuming this vector, all that is needed is the integer
it represents. Thus the FLP defines an algorithm for truncating the input to
the length of the aggregated output:

* `Flp.truncate(input: Vec[Field]) -> Vec[Field]` maps an encoded input (e.g.,
  the bit-encoding of the input) to an aggregatable output (e.g., the singleton
  vector containing the input). The length of the input MUST be `INPUT_LEN` and
  the length of the output MUST be `OUTPUT_LEN`.

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
aggregation, and unsharding are described in the remaining subsections. These
methods refer to constants enumerated in {{prio3-const}}.

| Parameter         | Value             |
|:------------------|:------------------|
| `VERIFY_KEY_SIZE` | `Prg.SEED_SIZE`   |
| `NONCE_SIZE`      | `16`              |
| `ROUNDS`          | `1`               |
| `SHARES`          | in `[2, 256)`     |
| `Measurement`     | `Flp.Measurement` |
| `AggParam`        | `None`            |
| `Prep`            | `Tuple[Vec[Flp.Field], Optional[Bytes], Bytes]` |
| `OutShare`        | `Vec[Flp.Field]`  |
| `AggResult`       | `Flp.AggResult`   |
{: #prio3-param title="VDAF parameters for Prio3."}

| Variable                          | Value |
|:----------------------------------|:------|
| `DST_MEASUREMENT_SHARE: Unsigned` | 1     |
| `DST_PROOF_SHARE: Unsigned`       | 2     |
| `DST_JOINT_RANDOMNESS: Unsigned`  | 3     |
| `DST_PROVE_RANDOMNESS: Unsigned`  | 4     |
| `DST_QUERY_RANDOMNESS: Unsigned`  | 5     |
| `DST_JOINT_RAND_SEED: Unsigned`   | 6     |
| `DST_JOINT_RAND_PART: Unsigned`   | 7     |
{: #prio3-const title="Constants used by Prio3."}

### Sharding

Recall from {{flp}} that the FLP syntax calls for "joint randomness" shared by
the prover (i.e., the Client) and the verifier (i.e., the Aggregators). VDAFs
have no such notion. Instead, the Client derives the joint randomness from its
input in a way that allows the Aggregators to reconstruct it from their input
shares. (This idea is based on the Fiat-Shamir heuristic and is described in
Section 6.2.3 of {{BBCGGI19}}.)

The sharding algorithm involves the following steps:

1. Encode the Client's raw measurement as an input for the FLP
1. Shard the measurement into a sequence of measurement shares
1. Derive the joint randomness from the measurement shares and nonce
1. Run the FLP proof-generation algorithm using the derived joint randomness
1. Shard the proof into a sequence of proof shares
1. Return the public share, consisting of the joint randomness parts, and the
   input shares, each consisting of the measurement share, proof share, and
   blind of one of the Aggregators

The algorithm is specified below. Notice that only one set of input and proof
shares (called the "leader" shares below) are vectors of field elements. The
other shares (called the "helper" shares) are represented instead by PRG seeds,
which are expanded into vectors of field elements.

The definitions of constants and a few auxiliary functions are defined in
{{prio3-auxiliary}}.

~~~
def measurement_to_input_shares(Prio3, measurement, nonce, rand):
    l = Prio3.Prg.SEED_SIZE
    use_joint_rand = Prio3.Flp.JOINT_RAND_LEN > 0

    # Split the random input into the various seeds we'll need.
    if len(rand) != Prio3.RAND_SIZE:
        raise ERR_INPUT # unexpected length for random input
    seeds = [rand[i:i+l] for i in range(0,Prio3.RAND_SIZE,l)]
    if use_joint_rand:
        k_helper_seeds, seeds = front((Prio3.SHARES-1) * 3, seeds)
        k_helper_meas_shares = [
            k_helper_seeds[i]
            for i in range(0, (Prio3.SHARES-1) * 3, 3)
        ]
        k_helper_proof_shares = [
            k_helper_seeds[i]
            for i in range(1, (Prio3.SHARES-1) * 3, 3)
        ]
        k_helper_blinds = [
            k_helper_seeds[i]
            for i in range(2, (Prio3.SHARES-1) * 3, 3)
        ]
        (k_leader_blind,), seeds = front(1, seeds)
    else:
        k_helper_seeds, seeds = front((Prio3.SHARES-1) * 2, seeds)
        k_helper_meas_shares = [
            k_helper_seeds[i]
            for i in range(0, (Prio3.SHARES-1) * 2, 2)
        ]
        k_helper_proof_shares = [
            k_helper_seeds[i]
            for i in range(1, (Prio3.SHARES-1) * 2, 2)
        ]
        k_helper_blinds = [None] * (Prio3.SHARES-1)
        k_leader_blind = None
    (k_prove,), seeds = front(1, seeds)

    # Finish measurement shares and joint randomness parts.
    inp = Prio3.Flp.encode(measurement)
    leader_meas_share = inp
    k_joint_rand_parts = []
    for j in range(Prio3.SHARES-1):
        helper_meas_share = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_helper_meas_shares[j],
            Prio3.custom(DST_MEASUREMENT_SHARE),
            byte(j+1),
            Prio3.Flp.INPUT_LEN
        )
        leader_meas_share = vec_sub(leader_meas_share,
                                    helper_meas_share)
        if use_joint_rand:
            encoded = Prio3.Flp.Field.encode_vec(helper_meas_share)
            k_joint_rand_part = Prio3.Prg.derive_seed(
                k_helper_blinds[j],
                Prio3.custom(DST_JOINT_RAND_PART),
                byte(j+1) + nonce + encoded,
            )
            k_joint_rand_parts.append(k_joint_rand_part)

    # Finish joint randomness.
    if use_joint_rand:
        encoded = Prio3.Flp.Field.encode_vec(leader_meas_share)
        k_joint_rand_part = Prio3.Prg.derive_seed(
            k_leader_blind,
            Prio3.custom(DST_JOINT_RAND_PART),
            byte(0) + nonce + encoded,
        )
        k_joint_rand_parts.insert(0, k_joint_rand_part)
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            Prio3.joint_rand(k_joint_rand_parts),
            Prio3.custom(DST_JOINT_RANDOMNESS),
            b'',
            Prio3.Flp.JOINT_RAND_LEN,
        )
    else:
        joint_rand = []

    # Finish the proof shares.
    prove_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        k_prove,
        Prio3.custom(DST_PROVE_RANDOMNESS),
        b'',
        Prio3.Flp.PROVE_RAND_LEN,
    )
    proof = Prio3.Flp.prove(inp, prove_rand, joint_rand)
    leader_proof_share = proof
    for j in range(Prio3.SHARES-1):
        helper_proof_share = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_helper_proof_shares[j],
            Prio3.custom(DST_PROOF_SHARE),
            byte(j+1),
            Prio3.Flp.PROOF_LEN,
        )
        leader_proof_share = vec_sub(leader_proof_share,
                                     helper_proof_share)

    # Each Aggregator's input share contains its measurement share,
    # proof share, and blind. The public share contains the
    # Aggregators' joint randomness parts.
    input_shares = []
    input_shares.append(Prio3.encode_leader_share(
        leader_meas_share,
        leader_proof_share,
        k_leader_blind,
    ))
    for j in range(Prio3.SHARES-1):
        input_shares.append(Prio3.encode_helper_share(
            k_helper_meas_shares[j],
            k_helper_proof_shares[j],
            k_helper_blinds[j],
        ))
    public_share = Prio3.encode_public_share(k_joint_rand_parts)
    return (public_share, input_shares)
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
by a PRG seed. Each Aggregator derives a "part" of this seed from its input
share and the "blind" generated by the client. The seed is derived by hashing
together the parts, so before running the query-generation algorithm, it must
first gather the parts derived by the other Aggregators.

In order to avoid extra round of communication, the Client sends each Aggregator
a "hint" consisting of the other Aggregators' parts of the joint randomness
seed. This leaves open the possibility that the Client cheated by, say, forcing
the Aggregators to use joint randomness that biases the proof check procedure
some way in its favor. To mitigate this, the Aggregators also check that they
have all computed the same joint randomness seed before accepting their output
shares. To do so, they exchange their parts of the joint randomness along with
their verifier shares.

The definitions of constants and a few auxiliary functions are defined in
{{prio3-auxiliary}}.

~~~
def prep_init(Prio3, verify_key, agg_id, _agg_param,
              nonce, public_share, input_share):
    k_joint_rand_parts = Prio3.decode_public_share(public_share)
    (meas_share, proof_share, k_blind) = \
        Prio3.decode_leader_share(input_share) if agg_id == 0 else \
        Prio3.decode_helper_share(agg_id, input_share)
    out_share = Prio3.Flp.truncate(meas_share)

    # Compute joint randomness.
    joint_rand = []
    k_corrected_joint_rand, k_joint_rand_part = None, None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded = Prio3.Flp.Field.encode_vec(meas_share)
        k_joint_rand_part = Prio3.Prg.derive_seed(k_blind,
            Prio3.custom(DST_JOINT_RAND_PART),
            byte(agg_id) + nonce + encoded)
        k_joint_rand_parts[agg_id] = k_joint_rand_part
        k_corrected_joint_rand = Prio3.joint_rand(k_joint_rand_parts)
        joint_rand = Prio3.Prg.expand_into_vec(
            Prio3.Flp.Field,
            k_corrected_joint_rand,
            Prio3.custom(DST_JOINT_RANDOMNESS),
            b'',
            Prio3.Flp.JOINT_RAND_LEN,
        )

    # Query the measurement and proof share.
    query_rand = Prio3.Prg.expand_into_vec(
        Prio3.Flp.Field,
        verify_key,
        Prio3.custom(DST_QUERY_RANDOMNESS),
        nonce,
        Prio3.Flp.QUERY_RAND_LEN,
    )
    verifier_share = Prio3.Flp.query(meas_share,
                                     proof_share,
                                     query_rand,
                                     joint_rand,
                                     Prio3.SHARES)

    prep_msg = Prio3.encode_prep_share(verifier_share,
                                       k_joint_rand_part)
    return (out_share, k_corrected_joint_rand, prep_msg)

def prep_next(Prio3, prep, inbound):
    (out_share, k_corrected_joint_rand, prep_msg) = prep

    if inbound is None:
        return (prep, prep_msg)

    k_joint_rand_check = Prio3.decode_prep_msg(inbound)
    if k_joint_rand_check != k_corrected_joint_rand:
        raise ERR_VERIFY # joint randomness check failed

    return out_share

def prep_shares_to_prep(Prio3, _agg_param, prep_shares):
    verifier = Prio3.Flp.Field.zeros(Prio3.Flp.VERIFIER_LEN)
    k_joint_rand_parts = []
    for encoded in prep_shares:
        (verifier_share, k_joint_rand_part) = \
            Prio3.decode_prep_share(encoded)

        verifier = vec_add(verifier, verifier_share)

        if Prio3.Flp.JOINT_RAND_LEN > 0:
            k_joint_rand_parts.append(k_joint_rand_part)

    if not Prio3.Flp.decide(verifier):
        raise ERR_VERIFY # proof verifier check failed

    k_joint_rand_check = None
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        k_joint_rand_check = Prio3.joint_rand(k_joint_rand_parts)
    return Prio3.encode_prep_msg(k_joint_rand_check)
~~~
{: #prio3-prep-state title="Preparation state for Prio3."}

### Validity of Aggregation Parameters

Every input share MUST only be used once, regardless of the aggregation
parameters used.

~~~
def is_valid(agg_param, previous_agg_params):
    return len(previous_agg_params) == 0
~~~
{: #prio3-validity-scope title="Validity of aggregation parameters for Prio3."}

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
def agg_shares_to_result(Prio3, _agg_param,
                         agg_shares, num_measurements):
    agg = Prio3.Flp.Field.zeros(Prio3.Flp.OUTPUT_LEN)
    for agg_share in agg_shares:
        agg = vec_add(agg, Prio3.Flp.Field.decode_vec(agg_share))
    return Prio3.Flp.decode(agg, num_measurements)
~~~
{: #prio3-agg-output title="Computation of the aggregate result for Prio3."}

### Auxiliary Functions {#prio3-auxiliary}

This section defines a number of auxiliary functions referenced by the main
algorithms for Prio3 in the preceding sections.

The following method is called by the sharding and preparation algorithms to
derive the joint randomness.

~~~
def joint_rand(Prio3, k_joint_rand_parts):
    return Prio3.Prg.derive_seed(
        zeros(Prio3.Prg.SEED_SIZE),
        Prio3.custom(DST_JOINT_RAND_SEED),
        concat(k_joint_rand_parts),
    )
~~~

#### Message Serialization

The following methods are used for encoding and decoding the leader's (i.e.,
the Aggregator with ID `0`) VDAF input share. The leader's share consists of
the full-length measurement and proof shares.

~~~
def encode_leader_share(Prio3,
                        meas_share,
                        proof_share,
                        k_blind):
    encoded = Bytes()
    encoded += Prio3.Flp.Field.encode_vec(meas_share)
    encoded += Prio3.Flp.Field.encode_vec(proof_share)
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_blind
    return encoded

def decode_leader_share(Prio3, encoded):
    l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.INPUT_LEN
    encoded_meas_share, encoded = encoded[:l], encoded[l:]
    meas_share = Prio3.Flp.Field.decode_vec(encoded_meas_share)
    l = Prio3.Flp.Field.ENCODED_SIZE * Prio3.Flp.PROOF_LEN
    encoded_proof_share, encoded = encoded[:l], encoded[l:]
    proof_share = Prio3.Flp.Field.decode_vec(encoded_proof_share)
    l = Prio3.Prg.SEED_SIZE
    if Prio3.Flp.JOINT_RAND_LEN == 0:
        if len(encoded) != 0:
            raise ERR_DECODE
        return (meas_share, proof_share, None)
    k_blind, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return (meas_share, proof_share, k_blind)
~~~

Next, the methods below are used for encoding and decoding the helpers' (i.e.,
non-leader) VDAF input shares. Each consists of PRG seeds that are expanded
into the measurement and proof shares.

~~~
def encode_helper_share(Prio3,
                        k_meas_share,
                        k_proof_share,
                        k_blind):
    encoded = Bytes()
    encoded += k_meas_share
    encoded += k_proof_share
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += k_blind
    return encoded

def decode_helper_share(Prio3, agg_id, encoded):
    c_meas_share = Prio3.custom(DST_MEASUREMENT_SHARE)
    c_proof_share = Prio3.custom(DST_PROOF_SHARE)
    l = Prio3.Prg.SEED_SIZE
    k_meas_share, encoded = encoded[:l], encoded[l:]
    meas_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                           k_meas_share,
                                           c_meas_share,
                                           byte(agg_id),
                                           Prio3.Flp.INPUT_LEN)
    k_proof_share, encoded = encoded[:l], encoded[l:]
    proof_share = Prio3.Prg.expand_into_vec(Prio3.Flp.Field,
                                            k_proof_share,
                                            c_proof_share,
                                            byte(agg_id),
                                            Prio3.Flp.PROOF_LEN)
    if Prio3.Flp.JOINT_RAND_LEN == 0:
        if len(encoded) != 0:
            raise ERR_DECODE
        return (meas_share, proof_share, None)
    k_blind, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return (meas_share, proof_share, k_blind)
~~~

Next, the methods below are used for encoding and decoding the VDAF public share.

~~~
def encode_public_share(Prio3,
                        k_joint_rand_parts):
    encoded = Bytes()
    if Prio3.Flp.JOINT_RAND_LEN > 0:
        encoded += concat(k_joint_rand_parts)
    return encoded

def decode_public_share(Prio3, encoded):
    l = Prio3.Prg.SEED_SIZE
    if Prio3.Flp.JOINT_RAND_LEN == 0:
        if len(encoded) != 0:
            raise ERR_DECODE
        return None
    k_joint_rand_parts = []
    for i in range(Prio3.SHARES):
        k_joint_rand_part, encoded = encoded[:l], encoded[l:]
        k_joint_rand_parts.append(k_joint_rand_part)
    if len(encoded) != 0:
        raise ERR_DECODE
    return k_joint_rand_parts
~~~

Finally, the methods below are used for encoding and decoding the values
transmitted during VDAF preparation.

~~~
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
    if Prio3.Flp.JOINT_RAND_LEN == 0:
        if len(encoded) != 0:
            raise ERR_DECODE
        return (verifier, None)
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
    if Prio3.Flp.JOINT_RAND_LEN == 0:
        if len(encoded) != 0:
            raise ERR_DECODE
        return None
    l = Prio3.Prg.SEED_SIZE
    k_joint_rand_check, encoded = encoded[:l], encoded[l:]
    if len(encoded) != 0:
        raise ERR_DECODE
    return k_joint_rand_check
~~~

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
def prove_rand_len(Valid):
    """Length of the prover randomness."""
    return sum(map(lambda g: g.ARITY, Valid.GADGETS))

def query_rand_len(Valid):
    """Length of the query randomness."""
    return len(Valid.GADGETS)

def proof_len(Valid):
    """Length of the proof."""
    length = 0
    for (g, g_calls) in zip(Valid.GADGETS, Valid.GADGET_CALLS):
        P = next_power_of_2(1 + g_calls)
        length += g.ARITY + g.DEGREE * (P - 1) + 1
    return length

def verifier_len(Valid):
    """Length of the verifier message."""
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

1. Partition the prover randomness `prove_rand` into sub-vectors `seed_1, ...,
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

1. Partition `proof` into the sub-vectors `seed_1`, `coeff_1`, ..., `seed_H`,
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

### Prio3Count

Our first instance of Prio3 is for a simple counter: Each measurement is either
one or zero and the aggregate result is the sum of the measurements.

This instance uses PrgSha3 ({{prg-sha3}}) as its PRG. Its validity
circuit, denoted `Count`, uses `Field64` ({{fields}}) as its finite field. Its
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
| `Field`          | `Field64` ({{fields}})       |
{: title="Parameters of validity circuit Count."}

### Prio3Sum

The next instance of Prio3 supports summing of integers in a pre-determined
range. Each measurement is an integer in range `[0, 2^bits)`, where `bits` is an
associated parameter.

This instance of Prio3 uses PrgSha3 ({{prg-sha3}}) as its PRG. Its validity
circuit, denoted `Sum`, uses `Field128` ({{fields}}) as its finite field. The
measurement is encoded as a length-`bits` vector of field elements, where the
`l`th element of the vector represents the `l`th bit of the summand:

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

| Parameter        | Value                    |
|:-----------------|:-------------------------|
| `GADGETS`        | `[Range2]`               |
| `GADGET_CALLS`   | `[bits]`                 |
| `INPUT_LEN`      | `bits`                   |
| `OUTPUT_LEN`     | `1`                      |
| `JOINT_RAND_LEN` | `1`                      |
| `Measurement`    | `Unsigned`, in range `[0, 2^bits)` |
| `AggResult`      | `Unsigned`               |
| `Field`          | `Field128` ({{fields}})  |
{: title="Parameters of validity circuit Sum."}

### Prio3Histogram

This instance of Prio3 allows for estimating the distribution of the
measurements by computing a simple histogram. Each measurement is an arbitrary
integer and the aggregate result counts the number of measurements that fall in
a set of fixed buckets.

This instance of Prio3 uses PrgSha3 ({{prg-sha3}}) as its PRG. Its validity
circuit, denoted `Histogram`, uses `Field128` ({{fields}}) as its finite
field. The measurement is encoded as a one-hot vector representing the bucket
into which the measurement falls (let `bucket` denote a sequence of
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

The validity circuit uses `Range2` (see {{prio3sum}}) as its single gadget. It
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

| Parameter        | Value                   |
|:-----------------|:------------------------|
| `GADGETS`        | `[Range2]`              |
| `GADGET_CALLS`   | `[buckets + 1]`         |
| `INPUT_LEN`      | `buckets + 1`           |
| `OUTPUT_LEN`     | `buckets + 1`           |
| `JOINT_RAND_LEN` | `2`                     |
| `Measurement`    | `Integer`               |
| `AggResult`      | `Vec[Unsigned]`         |
| `Field`          | `Field128` ({{fields}}) |
{: title="Parameters of validity circuit Histogram."}

# Poplar1 {#poplar1}

This section specifies Poplar1, a VDAF for the following task. Each Client holds
a string of length `BITS` and the Aggregators hold a set of `l`-bit strings,
where `l <= BITS`. We will refer to the latter as the set of "candidate
prefixes". The Aggregators' goal is to count how many inputs are prefixed by
each candidate prefix.

This functionality is the core component of the Poplar protocol {{BBCGGI21}},
which was designed to compute the heavy hitters over a set of input strings. At
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
   Otherwise compute the next set of candidate prefixes, e.g., for each `p` in
   `H`, add `p || 0` and `p || 1` to the set. Repeat step 3 with the new set of
   candidate prefixes.

Poplar1 is constructed from an "Incremental Distributed Point Function (IDPF)",
a primitive described by {{BBCGGI21}} that generalizes the notion of a
Distributed Point Function (DPF) {{GI14}}. Briefly, a DPF is used to distribute
the computation of a "point function", a function that evaluates to zero on
every input except at a programmable "point". The computation is distributed in
such a way that no one party knows either the point or what it evaluates to.

An IDPF generalizes this "point" to a path on a full binary tree from the root
to one of the leaves. It is evaluated on an "index" representing a unique node
of the tree. If the node is on the programmed path, then the function evaluates
to a non-zero value; otherwise it evaluates to zero. This structure allows an
IDPF to provide the functionality required for the above protocol: To compute
the hit count for an index, just evaluate each set of IDPF shares at that index
and add up the results.

Consider the sub-tree constructed from a set of input strings and a target
threshold `t` by including all indices that prefix at least `t` of the input
strings. We shall refer to this structure as the "prefix tree" for the batch of
inputs and target threshold. To compute the `t`-heavy hitters for a set of
inputs, the Aggregators and Collector first compute the prefix tree, then
extract the heavy hitters from the leaves of this tree. (Note that the prefix
tree may leak more information about the set than the heavy hitters themselves;
see {{agg-param-privacy}} for details.)

Poplar1 composes an IDPF with the "secure sketching" protocol of {{BBCGGI21}}.
This protocol ensures that evaluating a set of input shares on a unique set of
candidate prefixes results in shares of a "one-hot" vector, i.e., a vector that
is zero everywhere except for one element, which is equal to one.

The remainder of this section is structured as follows. IDPFs are defined in
{{idpf}}; a concrete instantiation is given {{idpf-poplar}}. The Poplar1 VDAF is
defined in {{poplar1-construction}} in terms of a generic IDPF. Finally, a
concrete instantiation of Poplar1 is specified in {{poplar1-inst}};
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
instantiation of Poplar1 ({{poplar1-inst}}) will use a much larger field for
leaf nodes than for inner nodes. This is to ensure the IDPF is "extractable" as
defined in {{BBCGGI21}}, Definition 1.)

A concrete IDPF defines the types and constants enumerated in {{idpf-param}}. In
the remainder we write `Idpf.Vec` as shorthand for the type
`Union[Vec[Vec[Idpf.FieldInner]], Vec[Vec[Idpf.FieldLeaf]]]`. (This type denotes
either a vector of inner node field elements or leaf node field elements.) The
scheme is comprised of the following algorithms:

* `Idpf.gen(alpha: Unsigned, beta_inner: Vec[Vec[Idpf.FieldInner]], beta_leaf:
  Vec[Idpf.FieldLeaf], binder: Bytes, rand: Bytes[Idpf.RAND_SIZE]) -> (Bytes,
  Vec[Bytes])` is the randomized IDPF-key generation algorithm. (Input `rand`
  consists of the random bytes it consumes.) Its inputs are the index `alpha`
  the values `beta`, and a binder string. The value of `alpha` MUST be in range
  `[0, 2^BITS)`. The output is a public part that is sent to all Aggregators
  and a vector of private IDPF keys, one for each aggregator.

* `Idpf.eval(agg_id: Unsigned, public_share: Bytes, key: Bytes, level:
  Unsigned, prefixes: Vec[Unsigned], binder: Bytes) -> Idpf.Vec` is the
  deterministic, stateless IDPF-key evaluation algorithm run by each
  Aggregator. Its inputs are the Aggregator's unique identifier, the public
  share distributed to all of the Aggregators, the Aggregator's IDPF key, the
  "level" at which to evaluate the IDPF, the sequence of candidate prefixes,
  and a binder string. It returns the share of the value corresponding to each
  candidate prefix.

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
| RAND_SIZE  | Size of the random string consumed by the IDPF-key generator |
| KEY_SIZE   | Size in bytes of each IDPF key |
| FieldInner | Implementation of `Field` ({{field}}) used for values of inner nodes |
| FieldLeaf  | Implementation of `Field` used for values of leaf nodes |
{: #idpf-param title="Constants and types defined by a concrete IDPF."}

## Construction {#poplar1-construction}

This section specifies `Poplar1`, an implementation of the `Vdaf` interface
({{vdaf}}). It is defined in terms of any `Idpf` ({{idpf}}) for which
`Idpf.SHARES == 2` and `Idpf.VALUE_LEN == 2` and an implementation of `Prg`
({{prg}}). The associated constants and types required by the `Vdaf` interface
are defined in {{poplar1-param}}. The methods required for sharding,
preparation, aggregation, and unsharding are described in the remaining
subsections. These methods make use of constants defined in {{poplar1-const}}.

| Parameter         | Value             |
|:------------------|:------------------|
| `VERIFY_KEY_SIZE` | `Prg.SEED_SIZE` |
| `NONCE_SIZE`      | `16` |
| `ROUNDS`          | `2` |
| `SHARES`          | `2` |
| `Measurement`     | `Unsigned` |
| `AggParam`        | `Tuple[Unsigned, Vec[Unsigned]]` |
| `Prep`            | `Tuple[Bytes, Unsigned, Idpf.Vec]` |
| `OutShare`        | `Idpf.Vec` |
| `AggResult`       | `Vec[Unsigned]` |
{: #poplar1-param title="VDAF parameters for Poplar1."}

| Variable                  | Value |
|:--------------------------|:------|
| DST_SHARD_RAND: Unsigned  | 1     |
| DST_CORR_INNER: Unsigned  | 2     |
| DST_CORR_LEAF: Unsigned   | 3     |
| DST_VERIFY_RAND: Unsigned | 4     |
{: #poplar1-const title="Constants used by Poplar1."}


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
Putting everything together, the sharding algorithm is defined as
follows. Function `encode_input_shares` is defined in {{poplar1-auxiliary}}.

~~~
def measurement_to_input_shares(Poplar1, measurement, nonce, rand):
    l = Poplar1.Prg.SEED_SIZE

    # Split the random input into random input for IDPF key
    # generation, correlated randomness, and sharding.
    if len(rand) != Poplar1.RAND_SIZE:
        raise ERR_INPUT # unexpected length for random input
    idpf_rand, rand = front(Poplar1.Idpf.RAND_SIZE, rand)
    seeds = [rand[i:i+l] for i in range(0,3*l,l)]
    corr_seed, seeds = front(2, seeds)
    (k_shard,), seeds = front(1, seeds)

    prg = Poplar1.Prg(k_shard,
                      Poplar1.custom(DST_SHARD_RAND), b'')

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
    (public_share, keys) = Poplar1.Idpf.gen(measurement,
                                            beta_inner,
                                            beta_leaf,
                                            idpf_rand)

    # Generate correlated randomness used by the Aggregators to
    # compute a sketch over their output shares. PRG seeds are
    # used to encode shares of the `(a, b, c)` triples.
    # (See [BBCGGI21, Appendix C.4].)
    corr_offsets = vec_add(
        Poplar1.Prg.expand_into_vec(
            Poplar1.Idpf.FieldInner,
            corr_seed[0],
            Poplar1.custom(DST_CORR_INNER),
            byte(0) + nonce,
            3 * (Poplar1.Idpf.BITS-1),
        ),
        Poplar1.Prg.expand_into_vec(
            Poplar1.Idpf.FieldInner,
            corr_seed[1],
            Poplar1.custom(DST_CORR_INNER),
            byte(1) + nonce,
            3 * (Poplar1.Idpf.BITS-1),
        ),
    )
    corr_offsets += vec_add(
        Poplar1.Prg.expand_into_vec(
            Poplar1.Idpf.FieldLeaf,
            corr_seed[0],
            Poplar1.custom(DST_CORR_LEAF),
            byte(0) + nonce,
            3,
        ),
        Poplar1.Prg.expand_into_vec(
            Poplar1.Idpf.FieldLeaf,
            corr_seed[1],
            Poplar1.custom(DST_CORR_LEAF),
            byte(1) + nonce,
            3,
        ),
    )

    # For each level of the IDPF tree, shares of the `(A, B)`
    # pairs are computed from the corresponding `(a, b, c)`
    # triple and authenticator value `k`.
    corr_inner = [[], []]
    for level in range(Poplar1.Idpf.BITS):
        Field = Poplar1.Idpf.current_field(level)
        k = beta_inner[level][1] if level < Poplar1.Idpf.BITS - 1 \
            else beta_leaf[1]
        (a, b, c), corr_offsets = corr_offsets[:3], corr_offsets[3:]
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
{: #poplar1-mes2inp title="The sharding algorithm for Poplar1."}

### Preparation

The aggregation parameter encodes a sequence of candidate prefixes. When an
Aggregator receives an input share from the Client, it begins by evaluating its
IDPF share on each candidate prefix, recovering a `data_share` and `auth_share`
for each. The Aggregators use these and the correlation shares provided by the
Client to verify that the sequence of `data_share` values are additive shares of
a one-hot vector.

Aggregators MUST ensure the candidate prefixes are all unique and appear in
lexicographic order. (This is enforced in the definition of `prep_init()`
below.) Uniqueness is necessary to ensure the refined measurement (i.e., the sum
of the output shares) is in fact a one-hot vector. Otherwise, sketch
verification might fail, causing the Aggregators to erroneously reject a report
that is actually valid. Note that enforcing the order is not strictly necessary,
but this does allow uniqueness to be determined more efficiently.

The algorithms below make use of the auxiliary function `decode_input_share()`
defined in {{poplar1-auxiliary}}.

~~~
def prep_init(Poplar1, verify_key, agg_id, agg_param,
              nonce, public_share, input_share):
    (level, prefixes) = agg_param
    (key, corr_seed, corr_inner, corr_leaf) = \
        Poplar1.decode_input_share(input_share)
    Field = Poplar1.Idpf.current_field(level)

    # Ensure that candidate prefixes are all unique and appear in
    # lexicographic order.
    for i in range(1,len(prefixes)):
        if prefixes[i-1] >= prefixes[i]:
            raise ERR_INPUT # out-of-order prefix

    # Evaluate the IDPF key at the given set of prefixes.
    value = Poplar1.Idpf.eval(
        agg_id, public_share, key, level, prefixes)

    # Get shares of the correlated randomness for computing the
    # Aggregator's share of the sketch for the given level of the IDPF
    # tree.
    if level < Poplar1.Idpf.BITS - 1:
        corr_prg = Poplar1.Prg(corr_seed,
                                    Poplar1.custom(DST_CORR_INNER),
                                    byte(agg_id) + nonce)
        # Fast-forward the PRG state to the current level.
        corr_prg.next_vec(Field, 3 * level)
    else:
        corr_prg = Poplar1.Prg(corr_seed,
                                    Poplar1.custom(DST_CORR_LEAF),
                                    byte(agg_id) + nonce)
    (a_share, b_share, c_share) = corr_prg.next_vec(Field, 3)
    (A_share, B_share) = corr_inner[2*level:2*(level+1)] \
        if level < Poplar1.Idpf.BITS - 1 else corr_leaf

    # Compute the Aggregator's first round of the sketch. These are
    # called the "masked input values" [BBCGGI21, Appendix C.4].
    verify_rand_prg = Poplar1.Prg(verify_key,
        Poplar1.custom(DST_VERIFY_RAND),
        nonce + to_be_bytes(level, 2))
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
        if len(opt_sketch) == 0:
            return prep_mem # Output shares
        else:
            raise ERR_INPUT # prep message malformed

    raise ERR_INPUT # unexpected input

def prep_shares_to_prep(Poplar1, agg_param, prep_shares):
    if len(prep_shares) != 2:
        raise ERR_INPUT # unexpected number of prep shares
    (level, _) = agg_param
    Field = Poplar1.Idpf.current_field(level)
    sketch = vec_add(Field.decode_vec(prep_shares[0]),
                     Field.decode_vec(prep_shares[1]))
    if len(sketch) == 3:
        return Field.encode_vec(sketch)
    elif len(sketch) == 1:
        if sketch == Field.zeros(1):
            # In order to reduce communication overhead, let the
            # empty string denote a successful sketch verification.
            return b''
        else:
            raise ERR_VERIFY # sketch verification failed
    else:
        return ERR_INPUT # unexpected input length
~~~
{: #poplar1-prep-state title="Preparation state for Poplar1."}

### Validity of Aggregation Parameters

Aggregation parameters are valid for a given input share if no aggregation
parameter with the same level has been used with the same input share before.
The whole preparation phase MUST NOT be run more than once for a given
combination of input share and level.

~~~
def is_valid(agg_param, previous_agg_params):
    (level, _) = agg_param
    return all(
        level != other_level
        for (other_level, _) in previous_agg_params
    )
~~~
{: #poplar1-validity-scope title="Validity of aggregation parameters for
Poplar1."}

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

### Auxiliary Functions {#poplar1-auxiliary}

#### Message Serialization

This section defines methods for serializing input shares, as required by the
`Vdaf` interface. Optional serialization of the aggregation parameter is also
specified below.

Implementation note: The aggregation parameter includes the level of the IDPF
tree and the sequence of indices to evaluate. For implementations that perform
per-report caching across executions of the VDAF, this may be more information
than is strictly needed. In particular, it may be sufficient to convey which
indices from the previous execution will have their children included in the
next. This would help reduce communication overhead.

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
    l = Poplar1.Prg.SEED_SIZE
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
    if len(prefixes) > 2^32 - 1:
        raise ERR_INPUT # too many prefixes
    encoded = Bytes()
    encoded += to_be_bytes(level, 2)
    encoded += to_be_bytes(len(prefixes), 4)
    packed = 0
    for (i, prefix) in enumerate(prefixes):
        packed |= prefix << ((level+1) * i)
    l = floor(((level+1) * len(prefixes) + 7) / 8)
    encoded += to_be_bytes(packed, l)
    return encoded

def decode_agg_param(Poplar1, encoded):
    encoded_level, encoded = encoded[:2], encoded[2:]
    level = from_be_bytes(encoded_level)
    encoded_prefix_count, encoded = encoded[:4], encoded[4:]
    prefix_count = from_be_bytes(encoded_prefix_count)
    l = floor(((level+1) * prefix_count + 7) / 8)
    encoded_packed, encoded = encoded[:l], encoded[l:]
    packed = from_be_bytes(encoded_packed)
    prefixes = []
    m = 2^(level+1) - 1
    for i in range(prefix_count):
        prefixes.append(packed >> ((level+1) * i) & m)
    if len(encoded) != 0:
        raise ERR_INPUT
    return (level, prefixes)
~~~

## The IDPF scheme of {{BBCGGI21}} {#idpf-poplar}

In this section we specify a concrete IDPF, called IdpfPoplar, suitable for
instantiating Poplar1. The scheme gets its name from the name of the protocol of
{{BBCGGI21}}.

> TODO We should consider giving `IdpfPoplar` a more distinctive name.

The constant and type definitions required by the `Idpf` interface are given in
{{idpf-poplar-param}}.

IdpfPoplar requires a PRG for deriving the output shares, as well as a variety
of other artifacts used internally. For performance reasons, we instantiate
this object using PrgFixedKeyAes128 ({{prg-fixed-key-aes128}}). See
{{prg-vs-ro}} for justification of this choice.

| Parameter  | Value                   |
|:-----------|:------------------------|
| SHARES     | `2`                     |
| BITS       | any positive integer    |
| VALUE_LEN  | any positive integer    |
| KEY_SIZE   | `Prg.SEED_SIZE`         |
| FieldInner | `Field64` ({{fields}})  |
| FieldLeaf  | `Field255` ({{fields}}) |
{: #idpf-poplar-param title="Constants and type definitions for IdpfPoplar."}

### Key Generation

> TODO Describe the construction in prose, beginning with a gentle introduction
> to the high level idea.

The description of the IDPF-key generation algorithm makes use of auxiliary
functions `extend()`, `convert()`, and `encode_public_share()` defined in
{{idpf-poplar-helper-functions}}. In the following, we let `Field2` denote the
field `GF(2)`.

~~~
def gen(IdpfPoplar, alpha, beta_inner, beta_leaf, binder, rand):
    if alpha >= 2^IdpfPoplar.BITS:
        raise ERR_INPUT # alpha too long
    if len(beta_inner) != IdpfPoplar.BITS - 1:
        raise ERR_INPUT # beta_inner vector is the wrong size
    if len(rand) != IdpfPoplar.RAND_SIZE:
        raise ERR_INPUT # unexpected length for random input

    init_seed = [
        rand[:PrgFixedKeyAes128.SEED_SIZE],
        rand[PrgFixedKeyAes128.SEED_SIZE:],
    ]

    seed = init_seed.copy()
    ctrl = [Field2(0), Field2(1)]
    correction_words = []
    for level in range(IdpfPoplar.BITS):
        Field = IdpfPoplar.current_field(level)
        keep = (alpha >> (IdpfPoplar.BITS - level - 1)) & 1
        lose = 1 - keep
        bit = Field2(keep)

        (s0, t0) = IdpfPoplar.extend(seed[0], binder)
        (s1, t1) = IdpfPoplar.extend(seed[1], binder)
        seed_cw = xor(s0[lose], s1[lose])
        ctrl_cw = (
            t0[0] + t1[0] + bit + Field2(1),
            t0[1] + t1[1] + bit,
        )

        x0 = xor(s0[keep], ctrl[0].conditional_select(seed_cw))
        x1 = xor(s1[keep], ctrl[1].conditional_select(seed_cw))
        (seed[0], w0) = IdpfPoplar.convert(level, x0, binder)
        (seed[1], w1) = IdpfPoplar.convert(level, x1, binder)
        ctrl[0] = t0[keep] + ctrl[0] * ctrl_cw[keep]
        ctrl[1] = t1[keep] + ctrl[1] * ctrl_cw[keep]

        b = beta_inner[level] if level < IdpfPoplar.BITS-1 \
                else beta_leaf
        if len(b) != IdpfPoplar.VALUE_LEN:
            raise ERR_INPUT # beta too long or too short

        w_cw = vec_add(vec_sub(b, w0), w1)
        # Implementation note: Here we negate the correction word if
        # the control bit `ctrl[1]` is set. We avoid branching on the
        # value in order to reduce leakage via timing side channels.
        mask = Field(1) - Field(2) * Field(ctrl[1].as_unsigned())
        for i in range(len(w_cw)):
            w_cw[i] *= mask

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
         level, prefixes, binder):
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
            (seed, ctrl, y) = IdpfPoplar.eval_next(
                seed,
                ctrl,
                correction_words[current_level],
                current_level,
                bit,
                binder,
            )
        out_share.append(y if agg_id == 0 else vec_neg(y))
    return out_share

def eval_next(IdpfPoplar, prev_seed, prev_ctrl,
              correction_word, level, bit, binder):
    """
    Compute the next node in the IDPF tree along the path determined by
    a candidate prefix. The next node is determined by `bit`, the bit of
    the prefix corresponding to the next level of the tree.

    TODO Consider implementing some version of the optimization
    discussed at the end of [BBCGGI21, Appendix C.2]. This could on
    average reduce the number of AES calls by a constant factor.
    """

    Field = IdpfPoplar.current_field(level)
    (seed_cw, ctrl_cw, w_cw) = correction_word
    (s, t) = IdpfPoplar.extend(prev_seed, binder)
    s[0] = xor(s[0], prev_ctrl.conditional_select(seed_cw))
    s[1] = xor(s[1], prev_ctrl.conditional_select(seed_cw))
    t[0] += ctrl_cw[0] * prev_ctrl
    t[1] += ctrl_cw[1] * prev_ctrl

    next_ctrl = t[bit]
    (next_seed, y) = IdpfPoplar.convert(level, s[bit], binder)
    # Implementation note: Here we add the correction word to the
    # output if `next_ctrl` is set. We avoid branching on the value of
    # the control bit in order to reduce side channel leakage.
    mask = Field(next_ctrl.as_unsigned())
    for i in range(len(y)):
        y[i] += w_cw[i] * mask

    return (next_seed, next_ctrl, y)
~~~
{: #idpf-poplar-eval title="IDPF-evaluation generation algorithm of IdpfPoplar."}

### Auxiliary Functions {#idpf-poplar-helper-functions}

~~~
def extend(IdpfPoplar, seed, binder):
    prg = PrgFixedKeyAes128(seed, format_custom(1, 0, 0), binder)
    s = [
        prg.next(PrgFixedKeyAes128.SEED_SIZE),
        prg.next(PrgFixedKeyAes128.SEED_SIZE),
    ]
    b = prg.next(1)[0]
    t = [Field2(b & 1), Field2((b >> 1) & 1)]
    return (s, t)

def convert(IdpfPoplar, level, seed, binder):
    prg = PrgFixedKeyAes128(seed, format_custom(1, 0, 1), binder)
    next_seed = prg.next(PrgFixedKeyAes128.SEED_SIZE)
    Field = IdpfPoplar.current_field(level)
    w = prg.next_vec(Field, IdpfPoplar.VALUE_LEN)
    return (next_seed, w)

def encode_public_share(IdpfPoplar, correction_words):
    encoded = Bytes()
    control_bits = list(itertools.chain.from_iterable(
        cw[1] for cw in correction_words
    ))
    encoded += pack_bits(control_bits)
    for (level, (seed_cw, _, w_cw)) \
        in enumerate(correction_words):
        Field = IdpfPoplar.current_field(level)
        encoded += seed_cw
        encoded += Field.encode_vec(w_cw)
    return encoded

def decode_public_share(IdpfPoplar, encoded):
    l = floor((2*IdpfPoplar.BITS + 7) / 8)
    encoded_ctrl, encoded = encoded[:l], encoded[l:]
    control_bits = unpack_bits(encoded_ctrl, 2 * IdpfPoplar.BITS)
    correction_words = []
    for level in range(IdpfPoplar.BITS):
        Field = IdpfPoplar.current_field(level)
        ctrl_cw = (
            control_bits[level * 2],
            control_bits[level * 2 + 1],
        )
        l = PrgFixedKeyAes128.SEED_SIZE
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

Here, `pack_bits()` takes a list of bits, packs each group of eight bits into a
byte, in LSB to MSB order, padding the most significant bits of the last byte
with zeros as necessary, and returns the byte array. `unpack_bits()` performs
the reverse operation: it takes in a byte array and a number of bits, and
returns a list of bits, extracting eight bits from each byte in turn, in LSB to
MSB order, and stopping after the requested number of bits. If the byte array
has an incorrect length, or if unused bits in the last bytes are not zero, it
throws an error.

## Instantiation {#poplar1-inst}

By default, Poplar1 is instantiated with IdpfPoplar (`VALUE_LEN == 2`) and
PrgSha3 ({{prg-sha3}}). This VDAF is suitable for any positive value of `BITS`.
Test vectors can be found in {{test-vectors}}.

# Security Considerations {#security}

VDAFs have two essential security goals:

1. Privacy: An attacker that controls the network, the Collector, and a subset
   of Clients and Aggregators learns nothing about the measurements of honest
   Clients beyond what it can deduce from the aggregate result.

1. Robustness: An attacker that controls the network and a subset of Clients
   cannot cause the Collector to compute anything other than the aggregate of
   the measurements of honest Clients.

Formal definitions of privacy and robustness can be found in {{DPRS23}}. A VDAF
is the core cryptographic primitive of a protocol that achieves the above
privacy and robustness goals. It is not sufficient on its own, however. The
application will need to assure a few security properties, for example:

* Securely distributing the long-lived parameters, in particular the
  verification key.

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
picks bogus measurements for the remaining Clients.  Applications can guard
against these risks by adding additional controls on report submission,
such as client authentication and rate limits.

VDAFs do not inherently provide differential privacy {{Dwo06}}.  The VDAF approach
to private measurement can be viewed as complementary to differential privacy,
relying on non-collusion instead of statistical noise to protect the privacy of
the inputs.  It is possible that a future VDAF could incorporate differential
privacy features, e.g., by injecting noise before the sharding stage and
removing it after unsharding.

## Requirements for the Verification Key

The Aggregators are responsible for exchanging the verification key in advance
of executing the VDAF. Any procedure is acceptable as long as the following
conditions are met:

1. To ensure robustness of the computation, the Aggregators MUST NOT reveal the
   verification key to the Clients. Otherwise, a malicious Client might be able
   to exploit knowledge of this key to craft an invalid report that would be
   accepted by the Aggregators.

1. To ensure privacy of the measurements, the Aggregators MUST commit to the
   verification key prior to processing reports generated by Clients. Otherwise,
   a malicious Aggregator may be able to craft a verification key that, for a
   given report, causes an honest Aggregator to leak information about the
   measurement during preparation.

Meeting these conditions is required in order to leverage security analysis in
the framework of {{DPRS23}}. Their definition of robustness allows the attacker,
playing the role of a cohort of malicious Clients, to submit arbitrary reports
to the Aggregators and eavesdrop on their communications as they process them.
Security in this model is achievable as long as the verification key is kept
secret from the attacker.

The privacy definition of {{DPRS23}} considers an active attacker that controls
the network and a subset of Aggregators; in addition, the attacker is allowed to
choose the verification key used by each honest Aggregator over the course of
the experiment. Security is achievable in this model as long as the key is
picked at the start of the experiment, prior to any reports being generated.
(The model also requires nonces to be generated at random; see
{{nonce-requirements}} below.)

Meeting these requirements is relatively straightforward. For example, the
Aggregators may designate one of their peers to generate the verification key
and distribute it to the others. To assure Clients of key commitment, the
Clients and (honest) Aggregators could bind reports to a shared context string
derived from the key. For instance, the "task ID" of DAP {{DAP}} could be set to
the hash of the verification key; then as long as honest Aggregators only
consume reports for the task indicated by the Client, forging a new key after
the fact would reduce to finding collisions in the underlying hash function.
(Keeping the key secret from the Clients would require the hash function to be
one-way.) However, since rotating the key implies rotating the task ID, this
scheme would not allow key rotation over the lifetime of a task.

## Requirements for the Nonce {#nonce-requirements}

The sharding and preparation steps of VDAF execution depend on a nonce
associated with the Client's report. To ensure privacy of the underlying
measurement, the Client MUST generate this nonce using a CSPRNG. This is
required in order to leverage security analysis for the privacy definition of
{{DPRS23}}, which assumes the nonce is chosen at random prior to generating the
report.

Other security considerations may require the nonce to be non-repeating. For
example, to achieve differential privacy it is necessary to avoid "over
exposing" a measurement by including it too many times in a single batch or
across multiple batches. It is RECOMMENDED that the nonce generated by the
Client be used by the Aggregators for replay protection.

## Requirements for the Aggregation Parameters

As described in {{sec-daf-validity-scopes}} and {{sec-vdaf-validity-scopes}}
respectively, DAFs and VDAFs may impose restrictions on the re-use of input
shares. This is to ensure that correlated randomness provided by the Client
through the input share is not used more than once, which might compromise
confidentiality of the Client's measurements.

Protocols that make use of VDAFs therefore MUST call `Vdaf.is_valid`
on the set of all aggregation parameters used for a Client's input share, and
only proceed with the preparation and aggregation phases if that function call
returns `True`.

### Additional Privacy Considerations {#agg-param-privacy}

Aggregating a batch of reports multiple times, each time with a different
aggregation parameter, could result in information leakage beyond what is used
by the application.

For example, when Poplar1 is used for heavy hitters, the Aggregators learn not
only the heavy hitters themselves, but also the prefix tree (as defined in
{{poplar1}}) computed along the way. Indeed, this leakage is inherent to any
construction that uses an IDPF ({{idpf}}) in the same way. Depending on the
distribution of the measurements, the prefix tree can leak a significant amount
of information about unpopular inputs. For instance, it is possible (though
perhaps unlikely) for a large set of non-heavy-hitter values to share a common
prefix, which would be leaked by a prefix tree with a sufficiently small
threshold.

The only known, general-purpose approach to mitigating this leakage is via
differential privacy.

> TODO(issue #94) Describe (or point to some description of) the central DP
> mechanism for Poplar described in {{BBCGGI21}}.

## Pseudorandom Generators and Random Oracles {#prg-vs-ro}

The objects we describe in {{prg}} share a common interface, which we have
called Prg. However, these are not necessarily all modeled as cryptographic
Pseudorandom Generators in the security analyses of our protocols. Instead, most
of them are modeled as random oracles. For these use cases, we want to be
conservative in our assumptions, and hence prescribe PrgSha3 as the only
RECOMMENDED Prg instantiation.

The one exception is the PRG used in the Idpf implementation IdpfPoplar
{{idpf-poplar}}. Here, a random oracle is not needed to prove security, and
hence a construction based on fixed-key AES {{prg-fixed-key-aes128}} can be
used. However, as PrgFixedKeyAes128 has been shown to be differentiable from
a random oracle {{GKWWY20}}, it is NOT RECOMMENDED to use it anywhere else.

> OPEN ISSUE: We may want to drop the common interface for PRGs and random
> oracles. See issue #159.

# IANA Considerations

A codepoint for each (V)DAF in this document is defined in the table below. Note
that `0xFFFF0000` through `0xFFFFFFFF` are reserved for private use.

| Value                        | Scheme               | Type | Reference                |
|:-----------------------------|:---------------------|:-----|:-------------------------|
| `0x00000000`                 | Prio3Count         | VDAF | {{prio3count}}     |
| `0x00000001`                 | Prio3Sum           | VDAF | {{prio3sum}}       |
| `0x00000002`                 | Prio3Histogram     | VDAF | {{prio3histogram}} |
| `0x00000003` to `0x00000FFF` | reserved for Prio3 | VDAF | n/a                |
| `0x00001000`                 | Poplar1            | VDAF | {{poplar1-inst}}   |
| `0xFFFF0000` to `0xFFFFFFFF` | reserved           | n/a  | n/a                |
{: #codepoints title="Unique identifiers for (V)DAFs."}

> TODO Add IANA considerations for the codepoints summarized in {{codepoints}}.

--- back

# Acknowledgments
{:numbered="false"}

The security considerations in {{security}} are based largely on the security
analysis of {{DPRS23}}. Thanks to Hannah Davis and Mike Rosulek, who lent their
time to developing definitions and security proofs.

Thanks to Henry Corrigan-Gibbs, Armando Faz-Hernández, Simon Friedberger, Tim
Geoghegan, Mariana Raykova, Jacob Rothstein, Xiao Wang, and Christopher Wood for
useful feedback on and contributions to the spec.

# Test Vectors {#test-vectors}
{:numbered="false"}

> NOTE Machine-readable test vectors can be found at
> https://github.com/cfrg/draft-irtf-cfrg-vdaf/tree/main/poc/test_vec.

Test vectors cover the generation of input shares and the conversion of input
shares into output shares. Vectors specify the verification key, measurements,
aggregation parameter, and any parameters needed to construct the VDAF. (For
example, for `Prio3Sum`, the user specifies the number of bits for representing
each summand.)

Byte strings are encoded in hexadecimal. To make the tests deterministic, the
random inputs of randomized algorithms were fixed to the byte sequence starting
with `0`, incrementing by `1`, and wrapping at `256`:

~~~
0, 1, 2, ..., 255, 0, 1, 2, ...
~~~

## Prio3Count {#testvec-prio3count}
{:numbered="false"}

~~~
verify_key: "000102030405060708090a0b0c0d0e0f"
upload_0:
  measurement: 1
  nonce: "000102030405060708090a0b0c0d0e0f"
  public_share: >-
  input_share_0: >-
    e7a225b76420dd6dd0682380363bd782c8ca9ace6e7abc559dd873bafb503e3cc8b7
    9f3b2b8b0a14676172e46be2ce2f
  input_share_1: >-
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  round_0:
    prep_share_0: >-
      56df20acd68725eab85e44c706629df555d635a5b899df767fe28effd0c45f60
    prep_share_1: >-
      ab20df532878da1518b04178e08a39d0d40fdbfe1876e479dc5e94b43afc68d5
    prep_message: >-
  out_share_0:
    - e7a225b76420dd6d
  out_share_1:
    - 1b5dda489adf2292
agg_share_0: >-
  e7a225b76420dd6d
agg_share_1: >-
  1b5dda489adf2292
agg_result: 1
~~~

## Prio3Sum {#testvec-prio3sum}
{:numbered="false"}

~~~
bits: 8
verify_key: "000102030405060708090a0b0c0d0e0f"
upload_0:
  measurement: 100
  nonce: "000102030405060708090a0b0c0d0e0f"
  public_share: >-
    da6f5f000d95651e628464f5d086fde6a544464ac776c3812e2299cce1d29095
  input_share_0: >-
    2d97ed6ebc5f6748db3017211c7a31ceeba9500b8317a7f61578b85c08a7f7d95c63
    7bb14b95c062c74bd5b08625bdafbfd91fd01d22291b22b76e54a9be1f7e7015a396
    ae0d6d034b3d22795b3d98db2a9aa51b4ea56c247496d380367deb786a9b34d5cb88
    f0f43e5cb4ab71910c8fa20b0b518f7dd9ce11ec9bf4ce460c81d3e9db05c34e0f05
    14d53f5eadea231dbc1fc575ad52e01622671eaf49a66533a6511710eeea024df0da
    7e7d21451ff5fd9d38e36eee8b78bf7c0767b91e747c6b80d6ca6b726286edebeae4
    ff377040d87f84288f4d0e5960e27b79387caef816c27481be166b71d38d1695e5e5
    061c26f0f667f8fff3133c2ae3ac1853ac542a9af0b5e422764609abd882dedf6aa8
    c835228bbc0cb99a695e81c45a2876a961af0c680662de4400ec96004c45bdc32726
    68b01d7f861f2e03fc18adcc352bdeb7b06b39c2de749da45e9b48f46c45a390cb59
    455dbf3e8be5938203def1c45af5eb5bf2037be005768d74faf11efd255b699f5ae9
    bce8b3bf4688907d11ca89e7609b77c04abde845f63091b934017cf9a83f80eb86fd
    aa063630f86ee982d812062db0d1d760d84cfebbf99927cad516dd028bf2f9e9b7d2
    4aa0bd9c0cb16a46c469eacfe1c48b8d7bf626e5d3eedb3f3cc4972f14a4ba605565
    ec795dd9e68af4ac6185f370f1f77610c64b04d295007b34ed59ed7bceace7b9dea8
    8346a2ee47dfec257ede5cd6985c34abaf5983d067786a695ae1039b631555bbe876
    7baeedfe4f30df6b47479543c58a87e0aaf371234fc9094c4b2b79d025229634a3fd
    f68a36be0e8661a4f043504b7025f03f02e57704b4e410c60e69e88050d0c33ea71b
    c37f306c225f457fbab4929c65ba9401dc57a2dc31bd6d3f53099a00303132333435
    363738393a3b3c3d3e3f
  input_share_1: >-
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
    22232425262728292a2b2c2d2e2f
  round_0:
    prep_share_0: >-
      7ae72bff1c063181bfea222dd77bcd40c5d15f62174d4af984d728effb82edd302
      74c927a9ffa51b90c167c60b40c3cdda6f5f000d95651e628464f5d086fde6
    prep_share_1: >-
      8718d400e3f9ce7e2415ddd2288432bf85623812cb8a7cdfed57f5a417c422e25e
      84a67ab22c0b8ef7b0500c366feb95a544464ac776c3812e2299cce1d29095
    prep_message: >-
      4f351791f4d706a31c54ce699ef1af97
  out_share_0:
    - a18d0c7e2a74470727d4f628ff934e52
  out_share_1:
    - c472f381d58bb8f8bc2b09d7006cb1ad
agg_share_0: >-
  a18d0c7e2a74470727d4f628ff934e52
agg_share_1: >-
  c472f381d58bb8f8bc2b09d7006cb1ad
agg_result: 100
~~~

## Prio3Histogram {#testvec-prio3histogram}
{:numbered="false"}

~~~
buckets: [1, 10, 100]
verify_key: "000102030405060708090a0b0c0d0e0f"
upload_0:
  measurement: 50
  nonce: "000102030405060708090a0b0c0d0e0f"
  public_share: >-
    5e015517900cfc204138c24f808ddf4ee85eca87ba246cd715d116195172e500
  input_share_0: >-
    c269f2189db431ca2ebe7230bacd692ac02a7790818681b6ee5ecbd509587b2976c7
    897326840bb70083ee4df8ffe3dc65dbd71f56735a7dcc3a150da8e77171e6d380f2
    f6886845e310dabec4382a037ffc3520737af8874f5b2aec2fae1405cce12c257ef2
    9d22b3e511c30e8f9545251286b3ef3e3728256fc0cc21f5a8ea1d095187cc29132e
    52d24ad778920c740af125833e9a8d2f6b0255740e8d2a4e7b718446610a0650ba40
    61e6a3ee805c1dcffec90d00a3ea5817c9956459538c99efbb56b38eaa6aed93f5a0
    0f11ab0210af030b91c56e6b2b47bb30fcdc5f44a28b5d733e4661cbd736ae071e78
    4f99ba86ff2688f6751d2d16e80ddd99c9aceeb39ca660215f0fc1178f828e295840
    f941fa9a3217afd52b32ec6c8ee3ec58291f2c88e8150374ccfd503f07bc0021d6a9
    f1c81050df96ec5ce5c7d4f41255303132333435363738393a3b3c3d3e3f
  input_share_1: >-
    000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021
    22232425262728292a2b2c2d2e2f
  round_0:
    prep_share_0: >-
      ac872edaaaa532de61bcd63b168e522230b35064b09b6b35c1352bc354560fdeac
      684da645d3e509c6db8ba31f58dabb5e015517900cfc204138c24f808ddf4e
    prep_share_1: >-
      5578d125555acd21824329c4e971adddc07187f0f25a30ceba8407513f60f8e3d1
      5c17270c5631a718b3b4f5702aff54e85eca87ba246cd715d116195172e500
    prep_message: >-
      890bfbdf0c619d5c853a92e28bce41b3
  out_share_0:
    - c269f2189db431ca2ebe7230bacd692a
    - c02a7790818681b6ee5ecbd509587b29
    - 76c7897326840bb70083ee4df8ffe3dc
    - 65dbd71f56735a7dcc3a150da8e77171
  out_share_1:
    - 3f960de7624bce35b5418dcf453296d5
    - 41d5886f7e797e49f5a0342af6a784d6
    - 8c38768cd97bf448e37c11b207001c23
    - 9c2428e0a98ca58217c5eaf257188e8e
agg_share_0: >-
  c269f2189db431ca2ebe7230bacd692ac02a7790818681b6ee5ecbd509587b2976c789
  7326840bb70083ee4df8ffe3dc65dbd71f56735a7dcc3a150da8e77171
agg_share_1: >-
  3f960de7624bce35b5418dcf453296d541d5886f7e797e49f5a0342af6a784d68c3876
  8cd97bf448e37c11b207001c239c2428e0a98ca58217c5eaf257188e8e
agg_result: [0, 0, 1, 0]
~~~

## Poplar1 {#testvec-poplar1}
{:numbered="false"}

### Sharding
{:numbered="false"}

~~~
bits: 4
upload_0:
  measurement: 13
  nonce: "000102030405060708090a0b0c0d0e0f"
  public_share: >-
    8b332c8b09b84f5801ad1cfd30b0df3fba69d11ddf6065a9cdb87cb31579ba0443a4
    82f4ed21ac079b96f5944d1669a1159406148c00878ac9953bcfbadc0273042653fd
    0fae8c43ce746fd31f248d1cbf5d1bc01fe02a883571cf38a1a4c10f54d41979b6fc
    35ef1fb051f968ba4397b8e61a81d835fa7ee54b949a35abf76c13e0a9daf90f1528
    c40db5904b6e24d70116538b28c16d9dbfee45000fe14db45cafbb76768b28250e74
    6af691f4bb1619
  input_share_0: >-
    000102030405060708090a0b0c0d0e0f202122232425262728292a2b2c2d2e2f0734
    d55dcb0dec9599b96f38ca694d46056dbe5bb24ab41ca10faaa8249839632c6503c9
    795300a160e8c378762f3b329e9ebe6a081eaed2d72aaff0aeb52415211c314f609a
    0377e66b7be10a3d8d4e75890da4c93f62172bc07e54be31c060c5970b52af8e8633
    d63560f59fa0bb36
  input_share_1: >-
    101112131415161718191a1b1c1d1e1f303132333435363738393a3b3c3d3e3f9558
    af2229b50110d88e17b5b3a81902194a5eab5f8ad69f5c061f16ac1e92deadc3c6ed
    32714a3756fa68e580d523d6c0e4b92ba2277033a7adb060e7a2ee3b2e44591d7c99
    b1cbcbfc58e4ae9ef7613a1ff24e53201e7264940bed2cd318e8e80ab7aae630f342
    911d75c85980691d
~~~

### Preparation, Aggregation, and Unsharding
{:numbered="false"}

~~~
verify_key: "000102030405060708090a0b0c0d0e0f"
agg_param: (0, [0, 1])
upload_0:
  round_0:
    prep_share_0: >-
      a2d369b7ee44e5f8b903e889b37ea7ef4d29ee36d1abdb13
    prep_share_1: >-
      31182ff6e075b925a06c802eac3b14c1ad66ce991ca2ffc2
    prep_message: >-
      d2eb98add0ba9e1e587068b860babbb0fa8fbcd0ed4ddbd6
  round_1:
    prep_share_0: >-
      f4445265dc801ab5
    prep_share_1: >-
      0dbbad9a227fe54a
    prep_message: >-
  out_share_0:
    - d47170d4f804449e
    - e16add75c1d3f0c4
  out_share_1:
    - 2d8e8f2b06fbbb61
    - 2195228a3d2c0f3b
agg_share_0: >-
  d47170d4f804449ee16add75c1d3f0c4
agg_share_1: >-
  2d8e8f2b06fbbb612195228a3d2c0f3b
agg_result: [0, 1]
~~~

~~~
verify_key: "000102030405060708090a0b0c0d0e0f"
agg_param: (1, [0, 1, 2, 3])
upload_0:
  round_0:
    prep_share_0: >-
      94352b588fbd978be7ef2cacb83b1b64c1d11af699253242
    prep_share_1: >-
      4a3529a2b34159be1666064ba0a3a9cc4e72223ef6d0ac79
    prep_message: >-
      dd6a54fa43fff049fc5533f759dfc4300f443d3490f6debb
  round_1:
    prep_share_0: >-
      3dc2833b1f9010ee
    prep_share_1: >-
      c43d7cc4df6fef11
    prep_message: >-
  out_share_0:
    - c03ede9261e7f441
    - 8ef9fde3f50eb967
    - de3bb4acf0b9dff8
    - 24687334644cc809
  out_share_1:
    - 41c1216d9d180bbe
    - 7306021c09f14698
    - 23c44b530e462007
    - de978ccb9ab337f6
agg_share_0: >-
  c03ede9261e7f4418ef9fde3f50eb967de3bb4acf0b9dff824687334644cc809
agg_share_1: >-
  41c1216d9d180bbe7306021c09f1469823c44b530e462007de978ccb9ab337f6
agg_result: [0, 0, 0, 1]
~~~

~~~
verify_key: "000102030405060708090a0b0c0d0e0f"
agg_param: (2, [0, 2, 4, 6])
upload_0:
  round_0:
    prep_share_0: >-
      b640798e11bc37ac1f4981c99f0de15569b2bcc187d2f0f2
    prep_share_1: >-
      37a720e1739caca1b39b8fe97ce96e09277eee9cc694c2cf
    prep_message: >-
      ece7996f8658e44dd2e410b31cf74f5f8f30ab5e4f67b3c2
  round_1:
    prep_share_0: >-
      52a1848f964385f8
    prep_share_1: >-
      af5e7b7068bc7a07
    prep_message: >-
  out_share_0:
    - 352395a6c5e5804e
    - f9b61274892e76dd
    - b27e3eb4accbaa0a
    - 3b1c4a7f78d59935
  out_share_1:
    - ccdc6a59391a7fb1
    - 0849ed8b75d18922
    - 4f81c14b523455f5
    - c7e3b580862a66ca
agg_share_0: >-
  352395a6c5e5804ef9b61274892e76ddb27e3eb4accbaa0a3b1c4a7f78d59935
agg_share_1: >-
  ccdc6a59391a7fb10849ed8b75d189224f81c14b523455f5c7e3b580862a66ca
agg_result: [0, 0, 0, 1]
~~~

~~~
verify_key: "000102030405060708090a0b0c0d0e0f"
agg_param: (3, [1, 3, 5, 7, 9, 13, 15])
upload_0:
  round_0:
    prep_share_0: >-
      08efd12285f6e61599b2f9d941577fd843597d3b15f747d15b0b02daf6147752c6
      a7a72723fa0cad98c7c38a0716ff8833dd7f97d40ed374f963dd2bced921614ccd
      4dca993e6c4f5d1ab0ce9bf37df76b41e2c111868322dfc39b3145dfc832
    prep_share_1: >-
      04eb21e562d79e4255b2c5001ed5949fc01841f40d921fdf5c1100b5c993f34e9d
      a143558cc507fb9c3e3832d85b751575b8f5a102257b141b94027bc0a849013f46
      00d8257361b9d17e43f8cddc106b512f69c78b63bcde177e2d3c0cfb353d
    prep_message: >-
      1fdaf307e8cd8558ee64bfda5f2c14780472be2f238967b0b81c028fc0a86a2163
      49eb7cafbf14a83506fcbcdf71749ea8957539d7334e8914f8dfa68e826b628b13
      4ea2bfb1cd082f99f3c669d08e62bd704b899de93f01f741c96d51dafe6f
  round_1:
    prep_share_0: >-
      3e1ded312b78a4a2003d9365472d481c0adb6411d7049869693fb0b331750301
    prep_share_1: >-
      afe212ced4875b5dffc26c9ab8d2b7e3f5249bee28fb679696c04f4cce8afc7e
    prep_message: >-
  out_share_0:
    - 034a3226150cf3aa5e7f6e76b0c6a6b2aa9b750cdafdc6aae0ff2f4076894e2a
    - 1413b483f800a4faa67b1e1c6bb1be2a1c9cc590761edb85f77692b67f9c696a
    - 85591b91ee55008c7e7a58176d5bce3ca9974482b0c1aa2b7c69e0ab2e2e212c
    - 03d9e6cde627cc30ceac7a6b5e3192a382d641e761c05c01eea4bc543c7fc41d
    - cd8891db6ac77a7fbba2c401c1488b8d31ee2cbc65cb26d02cb037cc99d32543
    - 732e3e133c6d8c9a0f6647fc24be3c5d8a960b63c3163979fd4d42fd554a7812
    - 8a2964a89cd70d7ba65bb52f0f15fb2db7dc1c534d743e37f223f74b8489c85d
  out_share_1:
    - eab5cdd9eaf30c55a18091894f39594d55648af3250239551f00d0bf8976b155
    - d9ec4b7c07ff5b055984e1e3944e41d5e3633a6f89e1247a08896d4980639615
    - 68a6e46e11aaff738185a7e892a431c35668bb7d4f3e55d483961f54d1d1de53
    - ea26193219d833cf31538594a1ce6d5c7d29be189e3fa3fe115b43abc3803b62
    - 20776e2495388580445d3bfe3eb77472ce11d3439a34d92fd34fc833662cda3c
    - 7bd1c1ecc3927365f099b803db41c3a27569f49c3ce9c68602b2bd02aab5876d
    - 63d69b576328f28459a44ad0f0ea04d24823e3acb28bc1c80ddc08b47b763722
agg_share_0: >-
  034a3226150cf3aa5e7f6e76b0c6a6b2aa9b750cdafdc6aae0ff2f4076894e2a1413b4
  83f800a4faa67b1e1c6bb1be2a1c9cc590761edb85f77692b67f9c696a85591b91ee55
  008c7e7a58176d5bce3ca9974482b0c1aa2b7c69e0ab2e2e212c03d9e6cde627cc30ce
  ac7a6b5e3192a382d641e761c05c01eea4bc543c7fc41dcd8891db6ac77a7fbba2c401
  c1488b8d31ee2cbc65cb26d02cb037cc99d32543732e3e133c6d8c9a0f6647fc24be3c
  5d8a960b63c3163979fd4d42fd554a78128a2964a89cd70d7ba65bb52f0f15fb2db7dc
  1c534d743e37f223f74b8489c85d
agg_share_1: >-
  eab5cdd9eaf30c55a18091894f39594d55648af3250239551f00d0bf8976b155d9ec4b
  7c07ff5b055984e1e3944e41d5e3633a6f89e1247a08896d498063961568a6e46e11aa
  ff738185a7e892a431c35668bb7d4f3e55d483961f54d1d1de53ea26193219d833cf31
  538594a1ce6d5c7d29be189e3fa3fe115b43abc3803b6220776e2495388580445d3bfe
  3eb77472ce11d3439a34d92fd34fc833662cda3c7bd1c1ecc3927365f099b803db41c3
  a27569f49c3ce9c68602b2bd02aab5876d63d69b576328f28459a44ad0f0ea04d24823
  e3acb28bc1c80ddc08b47b763722
agg_result: [0, 0, 0, 0, 0, 1, 0]
~~~
