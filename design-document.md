# Prio v3 Design Document

## Architecture overview

Prio is a system and protocol for privately computing aggregation functions over private 
input. An aggregation function F is one that computes an output y = F(x[1],x[2],...) for inputs
x[i]. In general, Prio supports any aggregation function whose inputs can be encoded in a 
particular way. However, not all aggregation functions admit an efficient encoding, rendering
them impractical to implement. Thus, Prio supports a limited set of aggregation functions, 
some of which we highlight below:

- Simple statistics, including sum, mean, min, max, variance, and standard deviation;
- Bit vector OR and AND operations; and
- Data structures, like Bloom filters, counting Bloom filters, and count-min sketches, that approximately represent (multi-)sets of strings.

The applications for such aggregations functions are large, including, though not limited to:
counting the number of times a sensitive or private event occurs and approximating the frequency
that sensitive tokens or strings occur.

Client applications hold private inputs to the aggregation function, server processors,
or aggregators, invoke  multi-party computation to compute the output, and a final collector 
obtains the output of the aggregation function. At a high level, the flow of data through
these entities works roughly as follows:

~~~
                            +------------+     
 (1) Batch submission       |            |        (3) Collection
    +-----------------------> Aggregator +------------------+
    |                       |            |                  |
    |                       +-^-------^--+                  |
    |                         |       |                     |
    |                         |       |                     |
    |                         |       |  (2) MPC            |
+--------+           +--------v---+   |      eval      +----v------+
|        |           |            |   |                |           |
| Client +-----------> Aggregator |   |                | Collector |
|        |           |            |   |                |           |
+--------+           +--------^---+   |                +----^------+
    |                         |       |                     |
    |                         |       |                     | 
    |                         |       |                     |
    |                       +-v-------v--+                  |
    |                       |            |                  |
    +-----------------------> Aggregator +------------------+
                            |            |
                            +------------+
~~~ 

1. Applications split inputs into multiple (at least two) anonymized and encrypted shares,
   and upload each share to different aggregators that do not collude or otherwise share 
   data with one another. Applications continue this process until a "batch" of data is 
   collected. Upon receipt of a share, each aggregator verifies it for correctness. 
   (Details about input validation and how it pertains to system security properties is 
   in {{CITE}}.)
2. Each aggregator combines its shares into a partial sum. The aggregators then engage 
   in a multi-party protocol to combine these sums into a final, aggregated output.
3. The aggregated output is sent to the collector.

The output of a single batch aggregation reveals little to nothing beyond the value itself.

## Security overview

Prio assumes a powerful adversary with the ability to compromise an unbounded number of 
clients. In doing so, the adversary can input malicious (yet truthful) to the aggregation 
function. Prio also assumes that all but one server operates honestly, where a dishonest
server does not execute the protocol faithfully as specified. The system also assumes
that servers communicate over secure and mutually authenticated channels. In practice,
this can be done by TLS or some other form of application-layer authentication.

In the presence of this adversary, Prio provides two important properties for computing 
an aggergation function F:

1. Privacy. The adversary learns only the output of F computed over all client inputs, 
   and nothing else. 
1. Robustness. The adversary can influence the output of F only by reporting false 
   (untruthful) data. The output cannot be influenced in any other way.

There are several additional constraints that a Prio deployment must satisfy in order
to achieve these goals:

1. Minimum batch size. The aggregation batch size has an obvious impact on privacy.
   (A batch size of one hides nothing of the input.) {{questions-and-params}} discusses
   appropriate batch sizes and how it pertains to privacy in more detail.
2. Aggregation function choice. Some aggregation functions leak slightly more than the 
   function output itself. {{questions-and-params}} discusses the leakage profiles of 
   various aggregation functions in more detail.

## System requirements

### Data types

## System constraints

## System design

## Open questions and system parameters {#questions-and-params}

[[OPEN ISSUE: discuss batch size parameter and thresholds]]
[[OPEN ISSUE: discuss f^ leakage differences from HCG's paper]]

## Cryptographic dependencies
