# Verify

[TODO: Add an illustration of this sub-protocol.]

After the client uploads a report to the leader, the leader and helper run the
ZKP system specified by the PA protocol in order to verify that that their
shares correspond to a valid input. This phase involves two requests sent from
by the leader to the helper: the *verify start request*, and the *verify finish
request*. The contents of each request depend largely on the specific PA
protocol. However, both requests contain the helper's share of the report,
allowing the helper to run the verification protocol statelessly.

Another important feature of the verification protocol is that the leader may
"batch" multiple runs of the protocol into the same message flow. This allows
the leader to throttle the load on the helper endpoint.

At the end of this phase, the leader and helper will have decided whether a set
of client inputs are valid. For each valid input, they proceed as described in
[the "Collect" section](pa-collect.md).

## Verify Start

The leader begins the protocol by collecting a sequence of helper shares that
all correspond to the same helper endpoint URL, key configuration, and PA task.
For each share, it generates the first protocol messages as specified by the PA
protocol, then proceeds as follows.

**Request.**
Let `[helper]` denote the helper URL. The leader sends a POST request to
`[helper]/verify_start` with the following payload:

```
struct {
  PATask task;
  uint8 key_config_id;
  PAHelperShare shares<0..2^24-1>;       // Any number of helper shares
  select (PAVerifyStartReq.task.proto) { // Payload for each helper share
    case prio: PrioVerifyStartReq payloads<0..2^24-1>;
    case hits: HitsVerifyStartReq payloads<0..2^24-1>;
  }
} PAVerifyStartReq;
```

Each helper share has a corresponding message payload contained in
`PAVerifyStartReq.payloads`. This includes any protocol-specific information the
helper needs for the first step of input validation, e.g., the joint randomness
used by the leader and helper for the protocol run. Note that a well-formed
message contains as many payloads as shares, i.e., the sequence
`PAVerifyStartReq.payloads` has the same number of elements as
`PAVerifyStartReq.shares`. Moreover, the $i$-th payload should correspond to the
$i$-th share for each $0 < i \leq \ell$, where $\ell$ is the length of
`PAVerifyStartReq.payloads`.

[TODO: Instead of a sequence of shares and a sequence of payloads,
`PAVerifyStartReq` should have a sequence of (share, payload) pairs. (Here and
below.) This is difficult to express in TLS syntax because we have to select on
the protocol type.]

**Response.**
The helper handles well-formed requests as follows. (As usual, malformed requests are
handled as described in [the "Error handling" section](pa-error.md).) It first
looks for the PA parameters `PAParam` for which `PAVerifyStartReq.task.id ==
PAParam.task.id`. Next, it looks up the HPKE config and corresponding secret key
associated with `PAVerifyStartReq.key_config_id`. If not found, then it aborts
and alerts the leader with "unrecognized key config".

Finally, for each pair of shares and message payloads, the helper does as
follows. Let `share` denote the share. It computes the HPKE context as

```
context = SetupBaseR(share.enc, sk, PAParam.task)
```

where `sk` is the secret key corresponding to the HPKE key config. For each
report share `shaqre`, it derives is share of the input and proof from `context`
and `share.payload`  and computes its response to according to the PA protocol.
It responds to the POST request from the leader with status 200 and the
following message:

```
struct {
  PAProto proto;
  select (PAVerifyStartResp.proto) {
    case prio: PrioVerifyStartResp payloads<0..2^24-1>;
    case hits: HitsVerifyStartResp payloads<0..2^24-1>;
  }
} PAVerifyStartResp;
```

The $i$-th element of `PAVerifyStartResp.payloads` corresponds to the $i$-th element
of `PAVerifyStartReq.payloads` for each $0 < i \leq \ell$.

## Verify Finish

Next, the leader processes each message in `PAVerifyStartResp.payloads`
according to the PA protocol and sends a request to the helper, constructed as
follows.

**Request.**
The leader sends a POST request to `[helper]/verify_finish` with the following
message:

```
struct {
  PATask task;                     // Equal to PAVerifyStartReq.task
  uint8 key_config_id;             // Equal to PAVerifyStartReq.key_config_id
  PAHelperShare shares<0..2^24-1>; // Equal to PAVerifyStartReq.shares
  select (PAVerifyFinishReq.task.proto) {
    case prio: PrioVerifyFinishReq payloads<0..2^24-1>;
    case hits: HitsVerifyFinishReq payloads<0..2^24-1>;
  }
} PAVerifyFinishReq;
```

The $i$-th payload corresponds to the $i$-th payload of the `PAVerifyStartResp` sent
by the helper in response to the previous request.

**Response.**
The helper handles POST requests to `[helper]/verify_finish` as follows. It
begins just as before by looking up the PA parameters `PAParam` for which
`PAVerifyStartReq.task.id == PAParam.task.id`. Next, it looks up the HPKE config
and corresponding secret key associated with `PAVerifyStartReq.key_config_id`.
If not found, then it aborts and alerts the leader with "unrecognized key
config".

Finally, the helper responds to the POST request with status 200 and the
following message body:

```
struct {
  PAProto proto;
  select (PAVerifyFinishResp.proto) {
    case prio: PrioVerifyFinishResp payloads<0..2^16-1>;
    case hits: HitsVerifyFinishResp payloads<0..2^16-1>;
  }
} PAVerifyFinishResp;
```

The $i$-th payload corresponds to the $i$-th payload of the `PAVerifyFinishReq`.

## Decision

The helper decides whether each of input shares is valid after it responds
to the leader's verify finish request. Likewise, the leader decides whether each of
its shares is valid after processing the helper's response to its verify finish
request.

For each valid input, each aggregator derives its input share and stores it for
use in [the "Collect" phase](pa-collect.md) of the PA protocol.
