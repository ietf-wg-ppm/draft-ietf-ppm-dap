# Security overview

Prio assumes a powerful adversary with the ability to compromise an unbounded
number of clients. In doing so, the adversary can provide malicious (yet
truthful) inputs to the aggregation function. Prio also assumes that all but one
server operates honestly, where a dishonest server does not execute the protocol
faithfully as specified. The system also assumes that servers communicate over
secure and mutually authenticated channels. In practice, this can be done by TLS
or some other form of application-layer authentication.

In the presence of this adversary, Prio provides two important properties for
computing an aggregation function F:

1. Privacy. The aggregators and collector learn only the output of F computed
   over all client inputs, and nothing else.
1. Robustness. As long as the aggregators execute the input-validation protocol
   correctly, a malicious client can skew the output of F only by reporting
   false (untruthful) input. The output cannot be influenced in any other way.

There are several additional constraints that a Prio deployment must satisfy in
order to achieve these goals:

1. Minimum batch size. The aggregation batch size has an obvious impact on
   privacy. (A batch size of one hides nothing of the input.)
   {{questions-and-params}} discusses appropriate batch sizes and how they
   pertains to privacy in more detail.
2. Aggregation function choice. Some aggregation functions leak slightly more
   than the function output itself. {{questions-and-params}} discusses the
   leakage profiles of various aggregation functions in more detail.

## Threat model

In this section, we enumerate the actors participating in the Prio system and
enumerate their assets (secrets that are either inherently valuable or which
confer some capability that enables further attack on the system), the
capabilities that a malicious or compromised actor has, and potential
mitigations for attacks enabled by those capabilities.

This model assumes that all participants have previously agreed upon and
exchanged all shared parameters over some unspecified secure channel.

### Client/user

#### Assets

1. Unshared inputs. Clients are the only actor that can ever see the original
   inputs.
1. Unencrypted input shares.

#### Capabilities

1. Individual users can reveal their own input and compromise their own privacy.
     * Since this does not affect the privacy of others in the system, it is
       outside the threat model.
1. Clients (that is, software which might be used by many users of the system)
can defeat privacy by leaking input outside of the Prio system.
     * In the current threat model, other participants have no insight into what
       clients do besides uploading input shares. Accordingly, such attacks are
       outside of the threat model.
1. Clients may affect the quality of aggregations by reporting false input.
     * Prio can only prove that submitted input is valid, not that it is true.
       False input can be mitigated orthogonally to the Prio protocol (e.g., by
       requiring that aggregations include a minimum number of contributions)
       and so these attacks are considered to be outside of the threat model.
1. Clients can send invalid encodings of input.

#### Mitigations

1. The input validation protocol executed by the aggregators prevents either
individual clients or coalitions of clients from compromising the robustness
property.

### Aggregator

#### Assets

1. Unencrypted input shares.
1. Input share decryption keys.
1. Client identifying information.
1. Output shares.
1. Aggregator identity.

#### Capabilities

1. Aggregators may defeat the robustness of the system by emitting bogus output
   shares.
1. If clients reveal identifying information to aggregators (such as a trusted
   identity during client authentication), aggregators can learn which clients
   are contributing input.
     1. Aggregators may reveal that a particular client contributed input.
     1. Aggregators may attack robustness by selectively omitting inputs from
        certain clients.
          * For example, omitting submissions from a particular geographic
            region to falsely suggest that a particular localization is not
            being used.
1. Individual aggregators may compromise availability of the system by refusing
to emit output shares.
1. Input validity proof forging. Any aggregator can collude with a malicious
client to craft a proof share that will fool honest aggregators into accepting
invalid input.

#### Mitigations

1. The linear secret sharing scheme employed by the client ensures that privacy
   is preserved as long as at least one aggregator does not reveal its input
   shares.
1. If computed over a sufficient number of input shares, output shares reveal
   nothing about either the inputs or the participating clients.

### Leader

The leader is also an aggregator, and so all the assets, capabilities and
mitigations available to aggregators also apply to the leader.

#### Capabilities

1. Input validity proof verification. The leader can forge proofs and collude
   with a malicious client to trick aggregators into aggregating invalid inputs.
     * This capability is no stronger than any aggregator's ability to forge
       validity proof shares in collusion with a malicious client.
1. Relaying messages between aggregators. The leader can compromise availability
   by dropping messages.
     * This capability is no stronger than any aggregator's ability to refuse to
       emit output shares.
1. Shrinking the anonymity set. The leader instructs aggregators to construct
   output parts and so could request aggregations over few inputs.

#### Mitigations

1. Aggregators enforce agreed upon minimum aggregation thresholds to prevent
   deanonymizing.

### Collector

#### Capabilities

1. Advertising shared configuration parameters (e.g., minimum thresholds for
   aggregations, joint randomness, arithmetic circuits).
1. Collectors may trivially defeat availability by discarding output shares
   submitted by aggregators.

#### Mitigations

1. Aggregators should refuse shared parameters that are trivially insecure
   (i.e., aggregation threshold of 1 contribution).

### Aggregator collusion

If all aggregators collude (e.g. by promiscuously sharing unencrypted input
shares), then none of the properties of the system hold. Accordingly, such
scenarios are outside of the threat model.

### Attacker on the network

We assume the existence of attackers on the network links between participants.

#### Capabilities

1. Observation of network traffic. Attackers may observe messages exchanged
   between participants at the IP layer.
     1. The time of transmission of input shares by clients could reveal
        information about user activity.
          * For example, if a user opts into a new feature, and the client
            immediately reports this to aggregators, then just by observing
            network traffic, the attacker can infer what the user did.
     1. Observation of message size could allow the attacker to learn how much
        input is being submitted by a client.
          * For example, if the attacker observes an encrypted message of some
            size, they can infer the size of the plaintext, plus or minus the
            cipher block size. From this they may be able to infer which
            aggregations the user has opted into or out of.
1. Tampering with network traffic. Attackers may drop messages or inject new
   messages into communications between participants.

#### Mitigations

1. All messages exchanged between participants in the system should be
   encrypted.
1. All messages exchanged between aggregators, the collector and the leader
   should be mutually authenticated so that network attackers cannot impersonate
   participants.
1. Clients should be required to submit inputs at regular intervals so that the
   timing of individual messages does not reveal anything.
1. Clients should submit dummy inputs even for aggregations the user has not
   opted into.

[[OPEN ISSUE: The threat model for Prio --- as it's described in the original
paper and [BBG+19] --- considers **either** a malicious client (attacking
soundness) **or** a malicious subset of aggregators (attacking privacy). In
particular, soundness isn't guaranteed if any one of the aggregators is
malicious; in theory it may be possible for a malicious client and aggregator to
collude and break soundness. Is this a contingency we need to address? There are
techniques in [BBG+19] that account for this; we need to figure out if they're
practical.]]

## Future work and possible extensions

In this section we discuss attacks that are not considered in the above threat
model, and suggest mitigations that could be incorporated into implementations
of this protocol or future revisions of this specfication.

### Client authentication

Attackers can impersonate Prio clients and submit large amounts of false input
in order to spoil aggregations. Deployments could require clients to
authenticate before they may contribute inputs. For example, by requiring
submissions to be signed with a key trusted by aggregators. However some
deployments may opt to accept the risk of false inputs to avoid having to figure
out how to distribute trusted identities to clients.

### Client attestation

In the current threat model, servers participating in the protocol have no
insight into the activities of clients except that they have uploaded input into
a Prio aggregation, meaning that clients could covertly leak a user's data into
some other channel which compromises privacy. If we introduce the notion of a
trusted computing base which can attest to the properties or activities of a
client, then users and aggregators can be assured that their private data only
goes into Prio. For instance, clients could use the trusted computing base to
attest to software measurements over reproducible builds, or a trusted operating
system could attest to the client's network activity, allowing external
observers to be confident that no data is being exfiltrated.

### Trusted anonymizing and authenticating proxy

While the input shares transmitted by clients to aggregators reveal nothing
about the original input, the aggregator can still learn auxiliary information
received messages (for instance, source IP or HTTP user agent), which can
identify participating clients or permit some attacks on robustness. This is
worse if client authentication used, since incoming messages would be bound to a
cryptographic identity. Deployments could include a trusted anonymizing proxy,
which would be responsible for receiving input shares from clients, stripping
any identifying information from them (including client authentication) and
forwarding them to aggregators. There should still be a confidential and
authenticated channel from the client to the aggregator to ensure that no actor
besides the aggregator may decrypt the input shares.

### Multiple protocol runs

Prio is _robust_ against malicious clients, and _private_ against malicious
servers, but cannot provide robustness against malicious servers. Any aggregator
can simply emit bogus output shares and undetectably spoil aggregates. If enough
aggregators were available, this could be mitigated by running the protocol
multiple times with distinct subsets of aggregators chosen so that no aggregator
appears in all subsets and checking all the outputs against each other. If all
the protocol runs do not agree, then participants know that at least one
aggregator is defective, and it may be possible to identify the defector (i.e.,
if a majority of runs agree, and a single aggregator appears in every run that
disagrees). See
[#22](https://github.com/abetterinternet/prio-documents/issues/22) for
discussion.

## Security considerations

### Infrastructure diversity

Prio deployments should ensure that aggregators do not have common dependencies
that would enable a single vendor to reassemble inputs. For example, if all
participating aggregators stored unencrypted input shares on the same cloud
object storage service, then that cloud vendor would be able to reassemble all
the input shares and defeat privacy.
