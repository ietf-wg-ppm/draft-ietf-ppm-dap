# Configuration

**Tasks.**
Each PA protocol is associated with a *PA task* that specifies the measurements
that are to be collected and the protocol that will be used to collect them:

```
struct {
  uint16 version;
  uint16 id;
  PAProto proto;
} PATask;

enum { prio(0), hits(1) } PAProto;
```
[TODO: Decide how to serialize protocol messages. We're using TLS syntax for
now, but there's no reason to stick with it other than most folks are familiar
with it.]

The first field, `version` specifies the version of this document. The second
field, `id` is an opaque value used by the clients, aggregators, and collector
to uniquely identify the PA task at hand. We call it the *task id*. The last
field, `proto`, identifies the concrete PA protocol.

**Parameters.**
A PA task may have protocol-specific parameters associated to it. These are
encoded by the `PAParam` structure, which also encodes the task:

```
struct {
  PATask task;
  select (PAClientParam.task.proto) {
    case prio: PrioParam; // Defined in Section 3
    case hits: HitsParam; // Defined in Section 4
  }
} PAParam;
```

[TODO: Add batch parameters, including min/max batch size, batch time window,
etc.]

[OPEN ISSUE: Would it be useful if `PAoTask.id` were bigger so that task ids can
be more sparse?]

**Helper key configuration.**
Each helper specifies the
[HPKE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hpke/) public key the
client will use to encrypt the helper's share of the report. The public key and
associated parameters are structured as follows:

```
struct {
  uint8 id;
  HpkeKemId kem_id;
  HpkeKdfId kdf_id;
  HpkeAeadKdfId aead_id;
  HpkePublicKey public_key;
} HPKEKeyConfig;

opaque HpkePublicKey<0..2^16-1>;
uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
```

We call this the helper's *key configation*. The key configuration is used to
set up a base-mode HPKE context to use to derive symmetric keys for protecting
the shares sent to the helper via the leader. The *config id*,
`HPKEKeyConfig.id`, is forwarded by the client to the helper, who uses this
value to decide if it knows how to decrypt a share it receives.

**Pre-conditions.**
We assume the following conditions hold before the protocol begins:
1. The client, aggregators, and collector are configured with a specific PA task.
1. The client knows the URL of the leader endpoint, e.g., `example.com/metrics`.
   We write this URL as `[leader]` below. (We write `[helper]` for a helper's
   URL.)
1. The client and leader can establish a leader-authenticated TLS channel.
1. The leader and each helper can establish a leader-authenticated TLS channel.
1. Each helper has chosen an HPKE key pair.
1. The aggregators agree on a set of PA tasks, as well as the PA protocol and
   parameters used for each task.
