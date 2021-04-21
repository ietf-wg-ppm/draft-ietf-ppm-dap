# Introduction

This document describes a framework for specifying protocols for
privacy-preserving data-aggregation. Each protocol is executed by a large set of
clients and a small set of servers. The servers' goal is to compute some
aggregate statistic over the clients' inputs without learning the inputs
themselves. This is made possible by "distributing trust" among the servers in
such a way that, as long as at least one of them executes the protocol honestly,
inputs are never seen in the clear by any server.

This document is structured as follows.
- The rest of this section provides an overview of the framework.
- [Section 2](pa.md) specifies a protocol for a generic *private aggregation
  (PA) task*.
- [Section 3](prio.md) describes an instantiation of the PA protocol using Prio
  [GB17].
- [Section 4](hits.md) describes an instantiation of the PA protocol using the
  heavy hitters protocol of Boneh et al. [BBG+21].
- [Section 5](security.md) enumerates our security considerations.
- [Section 6](terms.md) provides a reference for frequently used terminology.

## Overview

The protocol is executed by a large set of clients and a small set of servers.
We call the servers the *aggregators*. Each client's input to the protocol is a
set of measurements (e.g., counts of some user behavior).  Given the input set
of measurements $x_1, ..., x_n$ held by $n$ users, the goal of a
*private aggregation (PA) protocol* is to compute $y = F(x_1, ..., x_n)$ for
some aggregation function $F$, while revealing nothing else about the
measurements.

### Private aggregation via secret sharing

The main cryptographic tool we'll use for achieving this privacy goal is
*additive secret sharing*. Rather than send its input in the clear, each client
"splits" its measurements into a sequence of *shares* and sends a share to each
of the aggregators. Additive secret sharing has two important properties:
- First, it's impossible to deduce the measurement without knowing *all* of the
  shares.
- Second, it allows the aggregators to compute the final output by first adding
  up their measurements shares locally, then combining the results to obtain the
  final output.

Consider an illustrative example. Suppose there are three clients and two
aggregators. Each client $i$ holds a single measurement in the form of a
positive integer $x_i$, and our goal is to compute the sum of the measurements
of all clients. In this case, the protocol input is a single measurement
consisting of a single positive integer; no additional encoding is done. Given
this input, the first client splits its measurement $x_1$ with additive
secret-sharing into a pair of integers $X_1^1$ and $X_1^2$ for which $x_1 =
X_1^1 + X_1^2$ modulo a prime number $p$. (For convenience, we will omit the
$\mod p$ operator in the rest of this section.) It then uploads $X_1^1$ to one
sever $X_1^2$ to the other. The second client splits its measurement $x_2$ into
$X_1^2$ and $X_2^2$, uploads them to the servers, and so on.

Now the first aggregator is in possession of shares $X_1^1$, $X_2^1$, and
$X_3^1$ and the second aggregator is in possession of shares  $X_2^1$, $X_2^2$,
and $X_2^3$. Each aggregator computes the sum of its shares; let $A_1$ denote
the first aggregator's share of the sum and let $A_2$ denote the second
aggregator's share of the sum. In the last step, aggregators combine their sum
shares to obtain the final output $y = A_1 + A_2$. This is correct because
modular addition is commutative. I.e.,

$$
\begin{aligned}
y &= A_1 + A_2\\
  &= \left(X_1^1 + X_2^1 + X_3^1\right) +
     \left(X_1^2 + X_2^2 + X_3^2\right)\\
  &= \left(X_1^1 + X_1^2\right) +
     \left(X_2^1 + X_2^2\right) +
     \left(X_3^1 + X_3^1\right)\\
  &= x_1 + x_2 + x_3\\
  &= F(x_1, x_2, x_3) \,.
\end{aligned}
$$

**Prio.**
This approach can be used to privately compute any function $F$ that can be
expressed as a function of the sum of the users' inputs. In Prio [BG17], each
user encodes its measurement as a sequence of elements over some prime field. It
then splits its input into a shares and sends each share to the aggregators. The
aggregators sum up their input shares. Once all the shares have been aggregated,
they combine their shares of the aggregate to get the final output.

Not all aggregate functions can be expressed this way efficiently, however. Prio
supports only a limited set of aggregation functions, some of which we highlight
below:

- Simple statistics, like sum, mean, min, max, variance, and standard deviation;
- histograms with fixed bin sizes (also allows estimation of quantiles, e.g.,
  the median);
- More advanced statistics, like linear regression;
- Bitwise-OR and -AND on bit strings; and
- Computation of data structures, like Bloom filters, counting Bloom filters,
  and count-min sketches, that approximately represent (multi-)sets of strings.

This variety of aggregate types is sufficient to support a wide variety of
data aggregation tasks.

**Hits.**
A common PA task that can't be solved efficiently with Prio is the
*$t$-heavy-hitters* problem [BBG+21]. In this setting, each user is in
possession of an $n$-bit string, and the goal is to compute the compute the set
of strings that occur at least $t$ times.

[TODO: Provide an overview of the protocol of [BBG+21] and provide some
intuition about how additive secret sharing is used. Be sure to introduce the
notion of distributed point functions.]

### Validating inputs in zero knowledge

An essential task of any data collection pipeline is ensuring that the input
data is "valid". Going back to the example above, it's often useful to assert
that each measurement is in a certain range, e.g., $[0, 2^k)$ for some $k$.
This straight-forward task is complicated in our setting by the fact that the
inputs are secret shared. In particular, a malicious client can corrupt the
computation by submitting random integers instead of a proper secret sharing of
a valid input.

To solve this problem, each PA protocol in this document specifies a
*zero-knowledge proof (ZKP) system* that allows the aggregators to verify that
their shares correspond to as valid input. The system needs to have the
following security properties (stated informally here):
1. *Completeness:* The verification procedure always succeeds on valid inputs.
1. *Soundness:* Except with negligible probability, the verification procedure
   always fails on invalid inputs.
1. *Zero-knowledge:* The aggregators learn nothing from running the verification
   beyond the input's validity.

After encoding its measurements as an input to the PA protocol, the client
generates a *proof* of the input's validity. It then splits the proof into
shares and sends a share of both the proof and input to each aggregator. The
aggregators use their shares of the proof to decide if their input shares
correspond to a valid input.

### Collecting reports

As noted above, each client has a collection of measurements that it
wants to send. Each measurement is characterized by a set of
parameters that are centrally configured and provided to each client:

- A unique identifier (e.g., "dns-queries-mean")
- A description of how to collect the measurement (e.g., "count
  the number of DNS queries")
- The statistic to be computed over the measurement values (e.g., mean)
- The rules for what constitutes a valid value (e.g., must be between 0
  and 10000)

Once the client has collected the measurements to send, it needs to
turn them into a set of reports. Naively, each measurement would be
sent in its own report, but it is also possible to have multiple
measurements in a single report; clients need to be configured with
the mapping from measurements to reports. The set of measurements
that go into a report is referred to as the "input" to the report.
Because each report is independent, for the remainder of this document
we focus on a single report and its inputs.

[NOTE(cjpatton): This paragraph is slightly misleading. If you want to do a
range check for the measurement (this will usually be necessary, IMO) then
you'll need a few extra field elements to encode the input.]
The client uses the statistic to be computed in order to know how to
encode the measurement. For instance, if the statistic is mean, then
the measurement can be encoded directly. However, if the statistic is
standard deviation, then the client must send both $x$ and $x^2$. Section
[TODO: cite to internal description of how to encode]
describes how to encode measurements for each statistic.
The client uses the validity rules to construct the zero knowledge
proof showing that the encoded measurement is valid.

### Data flow

[TODO: Rework this subsection so that all terms needed in the proceeding
sections are defined.]

[TODO: Explain that the downside of using secret sharing is that the protocol
requires at two servers to be online during the entire data aggregation
process. To ameliorate this problem, we run the protocol in parallel with
multiple pairs of aggregators.]

Each PA task in this document is divided into three sub-protocols as follows.

```
                    +------------+
                    |            |
                    |   Helper   <---------------+
                    |            |               |
                    +-----^------+               |
                          |                      |
                       2. |                   3. |
                          |                      |
+--------+  1.      +-----v------+         +-----v-----+
|        +---------->            |      3. |           |
| Client +---------->   Leader   +---------> Collector |
|        +---------->            |         |           |
+--------+          +-----^------+         +-----^-----+
                          |                      |
                       2. |                   3. |
                          |                      |
                    +-----V------+               |
                    |            |               |
                    |   Helper   <---------------+
                    |            |
                    +------------+
```

1. **Upload:** Each client assembles the measurements into an input for the given
   PA protocol. It generates a proof of its input's validity and splits the
   input and proof into two shares, one for the leader and another for a helper.
   Rather than send each share to each aggregator directly, the client encrypts
   each share under the helper's public key and sends the ciphertext to the
   leader. The client repeats this procedure for each helper specified by the
   leader.
1. **Verify:** The leader initializes the input-validation
   protocol by sending the encrypted shares to the aggregators. (Details about
   input validation and how it pertains to system security properties are in
   {{CITE}}.) If the input is deemed valid, then each aggregator stores its
   input share for processing later on.
1. **Collect:** Finally, the collector interacts with the aggregators in
   order to obtain the final output of the protocol.
