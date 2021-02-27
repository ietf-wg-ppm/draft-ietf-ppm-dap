# Prio v3 Design Document

## Terminology
1. Aggregator: A server that runs the input-validation protocol and accumulates
   input shares.
1. Client: the endpoint from which the user sends data to be aggregated, e.g., a
   web browser.
1. Input-validation protocol: The protocol executed by the client and aggregators
   in order to validate the clients's input without leaking its value to the
   aggregators.
1. Leader: A distinguished aggregator that coordinates input validation and data
   aggregation.

## Architecture overview

Prio is a system and protocol for privately computing aggregation functions over private 
input. An aggregation function F is one that computes an output y = F(x[1],x[2],...) for inputs
x[i]. In general, Prio supports any aggregation function whose inputs can be encoded in a 
particular way. However, not all aggregation functions admit an efficient encoding, rendering
them impractical to implement. Thus, Prio supports a limited set of aggregation functions, 
some of which we highlight below:

- Simple statistics, including sum, mean, min, max, variance, and standard deviation; 
  [[OPEN ISSUE: It's possible to estimate quantiles such as the median. How practical is this?]]
- Bit vector OR and AND operations; and
- Data structures, like Bloom filters, counting Bloom filters, and count-min sketches, that 
  approximately represent (multi-)sets of strings.

The applications for such aggregations functions are large, including, though not limited to:
counting the number of times a sensitive or private event occurs and approximating the frequency
that sensitive tokens or strings occur.

Client applications hold private inputs to the aggregation function, server processors,
or aggregators, run a protocol that validates each input x[1], x[2], ... and computes the
final output y. The final collector obtains the output of the aggregation function.

At a high level, the flow of data through these entities works roughly as follows:

~~~
                            +------------+     
                            |            |        
                            | Aggregator |
                            |            |
                            +-^-------^--+
                              |       |   
                          (2) |       | (3)
                              |       |    
+--------+           +--------v---+   |        +-----------+
|        |    (1)    |            <---+   (4)  |           |
| Client +----------->   Leader   +------------> Collector |
|        |           |            <---+        |           |
+--------+           +--------^---+   |        +-----------+
                              |       |       
                          (2) |       | (3)       
                              |       |        
                            +-v-------v--+     
                            |            |     
                            | Aggregator |
                            |            |
                            +------------+
~~~ 

1. Upload: Clients split inputs into s >= 2 shares, encrypt each share for a different 
   Aggregator, and send these encrypted shares to the Leader. Clients continue 
   this process until a "batch" of data is collected.
2. Verify: Upon receipt of an encrypted share, the Leader sends it to the respective 
   Aggregator. Each Aggregator decrypts the share, computes a proof from the respective
   share, sends this proof to the leader. Once the Leader collects all proofs for 
   the batch, it determines whether or not the data for each entry is correct. 
   (Details about input validation and how it pertains to system security properties 
   is in {{CITE}}.)
3. Aggregate: Assuming the input share is valid, the Leader instructs each Aggregator 
   to combine aggregate their corresponding input share locally. When complete, each
   Aggregator sends their aggregated input shares to the Leader, who then combines all
   aggregates into a final result. 
4. Collect: The aggregated output is sent to the Collector.

The output of a single batch aggregation reveals little to nothing beyond the value itself.

## Security overview

Prio assumes a powerful adversary with the ability to compromise an unbounded number of 
clients. In doing so, the adversary can provide malicious (yet truthful) inputs to the aggregation 
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

[[OPEN ISSUE: The threat model for Prio --- as it's described in the original
paper and [BBC+19] --- considers **either** a malicious client (attacking
soundness) **or** a malicious subset of aggregators (attacking privacy). In
particular, soundness isn't guaranteed if any one of the aggregators is
malicious; in theory it may be possible for a malicious client and aggregator to
collude and break soundness. Is this a contingency we need to address? There are
techniques in [BBC+19] that account for this; we need to figure out if they're
practical.]]

## System requirements

### Data types

## System constraints

## System design

## Open questions and system parameters {#questions-and-params}

[[OPEN ISSUE: discuss batch size parameter and thresholds]]
[[OPEN ISSUE: discuss f^ leakage differences from HCG's paper]]

## Cryptographic components

### The input-validation protocol

**Notation.**
Fix a finite field K. We let K^n denote the set of vectors over K of length n.
We write the linear, s-way secret sharing of an element x of K^n as {x:1}, ...,
{x:s}, where {x:i} is the share held by the i-th party. We write {x} as
shorthand for the sequence {x:1}, ..., {x:s}. Each {x:i} is also an element of
K^n.

Prio combines standard [linear secret
sharing](https://en.wikipedia.org/wiki/Secret_sharing#t_=_n) with a new type of
probabilistically checkable proof (PCP) system, called a fully linear PCP. The
input-input validation protocol can be described in terms of three main
algorithms:

1. pf := Prove(x) denotes generation of a proof pf of the validity of input x.
   This algorithm is executed by the client.
1. {vf:i} := Query({x:i}, {pf:i}, r) denotes computation of the verification
   share {vf:i} for input share {x:i} and proof share {pf:i}. This algorithm is
   executed by each of the aggregators; input r denotes the joint randomness
   shared by all of the aggregators.
1. b := Decide({vf}, r) denotes the execution of the decision procedure on input
   shares {vf} and joint randomness r. The output b is a boolean indicating
   whether the input is deemed valid. This algorithm is run by the leader.

The values above have following types:

1. Input x is an element of K^n for some integer n.
1. Proof pf is an element of K^p(n) for some function p.
1. The joint randomness r is an element of K^u(n) for some function u.
1. Each verification share {vf:i} is an element of K^v(n) for some function v.

Before the protocol begins, the aggregators agree on joint randomness r and
designate one of the aggregators as the leader. The protocol proceeds as
follows:

1. The client runs pf := Prove(x). It splits x and pf into {x} and {pf}
   respectively and sends ({x:i}, {pf:i}) to aggregator i.
1. Each aggregator i runs {vf:i} := Query({x:i}, {pf:i}, r) ands sends {vf:i} to
   the leader.
1. The leader runs b := Decide({vf}, r) and sends b to each of the aggregators.

If b=1, then each aggregator i adds its input share {x:i} into its share of the
aggregate. Once a sufficient number of inputs have been validated and
aggregated, the aggregators send their aggregate shares to the leader, who adds
them together to obtain the final result.

[[TODO: Sketch out the b=1 path.]]

**Proof generation and verification.**
[[TODO: Describe how to construct proof systems for languages recognized by
validity circuits with G-gates, a la [BCC+19, Theorem 4.3].]]

**Security parameters.**
[[TODO: Define completeness, soundness, and honest-verifier zero-knowledge for
fully linear PCPs and state bounds for [BBC+19, Theorem 4.3]. This bound will
guide the selection of the field best suited for the data type and
application.]]

**Consensus protocol.**
[[TODO: Describe how the aggregators pick the leader and the joint randomness.]]

**Key distribution.**
[[TODO: Decide how clients obtain aggregators' public keys.]]

### Changes to the input-validation protocol

**Coordinating state.**
The state of the input-validation protocol is maintained by the leader; except
for aggregation of the input shares, the other aggregators are completely
stateless. This is accomplished by making the following changes to the core
protocol.

1. The client sends all of its shares to the leader. To maintain privacy, the
   client encrypts each (input, proof) share under the public key of the share's
   recipient.
1. The leader forwards each encrypted share to its intended recipient. Each
   aggregator decrypts its input and proof share, computes its verification
   share, and sends its verification share to the aggregator as usual.
1. If b=1 in the last step, then the leader also sends along the encrypted input
   share to each aggregator so that they can decrypt and aggregate the share
   without needing to cache the input share from the previous step.

**Minimizing communication overhead.**
In most linear secret sharing schemes, the length of each share is equal to the
length of the input. Therefore, the communication overhead for the client is
O(s\*(n+p(n))). This can be reduced to O(s+n+p(n)) with the following standard
trick.

Let x be an element of K^n for some n. Suppose we split x into {x} by choosing
{x:1}, ..., {x:s-1} at random and letting {x:s} = x - ({x:1} + ... + {x:s-1}).
We could instead choose s-1 random seeds k[s-1], ..., k[s-1] for a pseudorandom
number generator PRG and let {x:i} = PRG(k[i], n) for each i. This effectively
"compresses" s-1 of the shares to O(1) space.

### Primitives

This section describes the core cryptographic primitives of the system.

#### Finite field arithmetic

The algorithms that comprise the input-validation protocol --- Prove, Query, and
Decide --- are constructed by generating and evaluating polynomials over a
finite field. As such, the main ingredient of Prio is an implementation of
arithmetic in a finite field suitable for the given application.

We will use a prime field. The choice of prime is influenced by the following
criteria:

1. **Field size.** How big the field needs to be depends on the type of data
   being aggregated and how many users there are. The field size also impacts
   the security level: the longer the validity circuit, the larger the field
   needs to be in order to affectively detect malicious clients.
1. **Fast polynomial operations.** In order to make Prio practical, it's
   important that implementations employ FFT to speed up polynomial operations.
   In particular, the prime modulus p should be chosen so that (p-1) = 2^n * s
   for large n and odd s. Then g^s is a principle, 2^n-th root of unity (i.e.,
   g^(s\*2^n) = 1), where g is the generator of the multiplicative subgroup.
   This fact allows us to quickly evaluate and interpolate polynomials at 2^d-th
   roots of unity for 1 <= d <= n.
1. **Highly composite subgroup.** Suppose that (p-1) = 2^n * s. It's best if s
   is highly composite because this minimizes the number of multiplications
   required to compute the inverse or apply Fermat's Little Theorem. (See
   [BBC+19, Section 5.2].)
1. **Code opttimziation.** [[TODO: What properties of the field make
   it possible to write faster implementations?]]

The table below lists parameters that meet these criteria at various levels of
security. (Note that \#2 is the field used in "Prio v2".) The "bits" column
indicates the size of the prime. For example, for p=3221225473,
bits=log2(3221225473), which is approximately 31.53.

| # | bits   | p                                      | g  | n   | s                |
|---|--------|----------------------------------------|----|-----|------------------|
| 1 | 31.58  | 3221225473                             | 5  | 30  | 3                |
| 2 | 31.99  | 4293918721                             | 19 | 20  | 3^2 * 5 * 7 * 13 |
| 3 | 63.75  | 15564440312192434177                   | 5  | 59  | 3^3              |
| 4 | 66.17  | 83010348331692982273                   | 11 | 63  | 3^2              |
| 5 | 122.81 | 9304595970494411110326649421962412033  | 3  | 120 | 7                |
| 6 | 125.81 | 74769074762901517850839147140769382401 | 7  | 118 | 3^2 * 5^2        |

**Finding suitable primes.**
One way to find suitable primes is to first choose choose n, then "probe" to
find a prime of the desired size. The following SageMath script prints the
parameters of a number of primes larger than 2^n for a given n:

```
n = 116
for s in range(0,1000,1):
    N = 2^n
    p = (N*s).next_prime()
    if p-(N*s) == 1:
        bits = round(math.log2(p), 2)
        print(bits, p, GF(p).multiplicative_generator(), n, factor(s))
```

#### Key encapsulation

Our instantiation of the input-validation protocol involves two additional
operations: public key encryption and cryptographically secure pseudorandom
number generation (CSPRNG). The combination of these primitives that we use here
allows us to make an additional simplification. We assume that clients communicate
with the leader over a confidential and authenticated channel, such as TLS. As a
result, we only need to encrypt CSPRNG seeds, which requires only a
key-encapsulation mechanism (KEM) rather than full-blown encryption.

A KEM is comprised of two algorithms:

1. (c, k) := Encaps(pk) denotes generation and encapsulation of symmetric key k
   under the recipient's public key pk.
1. k := Decaps(sk, c) denotes decapsulation of symmetric key k under the
   recipient's secret key sk.

To generate an aggregator's share, the client runs (c[i], k[i]) := Encaps(pk[i])
and sends c[i] to the aggregator. To compute its share, the aggregator would run
k[i] := Decaps(sk[i], c[i]) and compute its share as {x:i} = PRG(k[i], n).

[HPKE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/) is a natural
candidate for instantiating the KEM. In "Export-Only" mode, HPKE provides an
efficient scheme with all the cryptographic agility we would ever need. And
although it's still an Internet-Draft, it has high quality implementations in a
variety of languages.

[[TODO: Specify how HPKE is used to implement Encaps() and Decaps().]]

#### Pseudorandom number generation

A suitable PRG will have the following syntax. Fix a finite field K:

1. x := PRG(k, n) denotes generation of a pseudorandom element x of K^n, i.e., a
   vector of n elements of K.

This can be instantiated using a standard stream cipher, e.g.., ChaCha20 as
follows. Interpret k as the cipher key, and using a fixed nonce, generate l\*n
bytes of output, where l is the number of bytes needed to encode an element of
K, then map each chunk of l bytes to an element of K by interpreting the chunk
as an l-byte integer and reducing it modulo the prime modulus.

[[OPEN ISSUE: Mapping the output of PRG(.,.) to a vector over K induces a
small amount of bias on the output. How much bias is induced depends on the how
close the prime is to a power of 2. Should this be a criterion for selecting the
prime?]]

## References

* [BBC+19] Boneh et al. "Zero-Knowledge Proofs on Secret-Shared Data via Fully
  Linear PCPs". Crypto 2019.
