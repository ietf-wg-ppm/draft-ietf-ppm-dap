## Resources

DAP is structured as an HTTP-based application with the following resources:

- HPKE configurations
- Reports
- Aggregation jobs
- Aggregate shares
- Collections

A resource's path is resolved relative to a server's base URL to construct a resource URI. Deployments may host resource paths arbitrarily deep relative to their domain. Paths are generally structured as `/resource-type/{resource-id}`. Anywhere `{resource-id}` (e.g., `{task-id}` or `{report-id}`) occurs in a URI is to be understood as the URL-safe, unpadded base64 representation of the resource's identifier, which itself is usually 16 random bytes (some are 32, but https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/349 will normalize them to 16).

Some resources are owned by another resource, and so their URI will contain two identifiers. For instance, a report belongs to a task, so the URI is `[base]/tasks/{task-id}/reports/{report-id}`.

Generally, if a resource supports the `GET` method, it also supports `HEAD`. The response to `HEAD` is exactly the same as `GET`, but the response contains no body.

If an HTTP method is listed in a resource's required HTTP methods, implementations MUST provide responses as indicated. Otherwise, implementations MAY implement methods on resources however they wish, including returning an error like HTTP 405 Method Not Allowed.

We use HTTP `PUT` requests for idempotent creation of resources. Server responses to `PUT` requests follow [RFC 9110 section 9.3.4](https://httpwg.org/specs/rfc9110.html#rfc.section.9.3.4).

Finally, a quick reminder of some HTTP semantics: `GET` and `PUT` are idempotent (i.e., the same request may be made multiple times without changing state in the server more than once, and the response will be the same each time). `POST` is not idempotent. `GET` requests may not have bodies.

We care a lot about idempotence because we need to account for cases where an HTTP client (e.g., the collector obtaining aggregate shares from the leader, or the leader driving the aggregation sub-protocol in the helper) makes a request but never sees the response, and thus needs a way to recover from this state of uncertainty.

### HPKE configurations

This proposal deliberately does not address any of the open questions or issues around multiple HPKE configurations or negotiation (see #248) and preserves the existing `hpke_config` endpoint unchanged, in the interest of containing the scope of this proposal.

#### Path

`/hpke_config[?task_id=task-id]`

The `task_id` query parameter is optional, as described in https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1.

#### Representation

Uses the existing [`struct HpkeConfig`](https://www.ietf.org/archive/id/draft-ietf-ppm-dap-02.html#section-4.3.1-6).

```
struct {
  HpkeConfigId id;
  HpkeKemId kem_id;
  HpkeKdfId kdf_id;
  HpkeAeadKdfId aead_id;
  HpkePublicKey public_key;
} HpkeConfig;
```

#### Required HTTP methods

##### GET/HEAD

The response body is a `struct HpkeConfig` representing the server's current `hpke_config`.

### Reports

#### Path

`/tasks/{task-id}/reports/{report-id}`

`report-id` uniquely identifies a report in a task. It is chosen by the client when uploading a report.

#### Representation

```
struct {
  Time time;
  Extension extensions<0..2^16-1>;
} ReportMetadata;

struct {
  ReportMetadata metadata;
  opaque public_share<0..2^32-1>;
  HpkeCiphertext encrypted_input_shares<1..2^32-1>;
} Report;
```

#### Required HTTP methods

##### PUT

Idempotent upload of a report to an aggregator. The request body is a `struct Report`. Once uploaded, a report is immutable, meaning that subsequent `PUT` requests to a particular report resource that vary fields of `struct Report` MUST be rejected by the leader.

This is analogous to DAP-02's `POST /upload`.

### Aggregation jobs

Only the helper supports this resource.

#### Path

`/tasks/{task-id}/aggregation_jobs`

##### PUT

PUT to the aggregation jobs resource is how the leader creates an aggregate job in the helper. The body is an `AggregateJob` (see resource "An aggregation job", below) where `round` is 0 and `prepare_steps` is a list of `struct PrepareStep`s in state `PrepareStepState::start`.

If successful, the helper's response is a redirect to a URI for the aggregation job, whose body is a `struct AggregateJob` where round is 1 and `prepare_steps` is a list of `struct PrepareStep`s in state `PrepareStepState::continued` that contains the helper's first-round VDAF prepare messages, or errors if `vdaf.prepare` failed for any report.

Once created, an aggregation job resource cannot be mutated with `PUT` requests.

This is analogous to DAP-02's `POST /aggregate` with an `AggregateInitReq`.

This request is idempotent (a `PartialBatchSelector` and `agg_param` uniquely identify an aggregation job), so if a helper receives multiple PUT requests for some aggregation job and the members of `AggregateJobPutReq` don't change, the helper can return 200 OK.

If the task has expired, then the helper should reject the request.

### An aggregation job

Only the helper supports this resource.

#### Path

Implementation defined (see PUT on the "Aggregation jobs" resource).

#### Representation

```
struct {
  QueryType query_type;
  select (PartialBatchSelector.query_type) {
    case time_interval: Interval batch_interval;
    case fixed_size: BatchID batch_id;
  };
} PartialBatchSelector;

enum {
  start(0),
  continued(1),
  finished(2),
  failed(3),
  (255),
} PrepareStepState;

struct {
  ReportMetadata metadata;
  opaque public_share<0..2^32-1>;
  HpkeCiphertext encrypted_input_share;
} ReportShare;

struct {
  ReportID report_id;
  PrepareStepState prepare_step_state;
  select (PrepareStep.prepare_step_state) {
    case start: ReportShare;
    case continued: opaque prep_msg<0..2^32-1>; /* VDAF preparation message */
    case finished: Empty;
    case failed: ReportShareError;
  }
} PrepareStep;

struct {
  PartialBatchSelector part_batch_selector;
  opaque agg_param<0..2^16-1>;
  u16 round;
  PrepareStep prepare_steps<1..2^32-1>;
} AggregateJob
```

See "POST", below, for explanation and justification of the `round` field.

#### Required HTTP methods

##### POST

POST to an aggregate job is how the leader steps an aggregate job. The request body is a `struct AggregateJob` where `prepare_steps` contains the leader's current-round prepare messages, and `round` is the number of the current round. The response is a `struct AggregateJob` where `prepare_steps` contains the helper's next-round prepare messages. The response's `round` field will be one more than the request's `round`.

We use a POST here because this request is _not_ idempotent. Suppose the leader sends `POST {aggregation-job-uri}` where the body has `round = 2`, and that this is successfully handled by the helper. Besides generating the response, this will have the side effect of advancing the state in the helper to round 3. If the leader were to resend the `POST /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` with `round = 1`, then the request should be rejected by the helper, because it has advanced to the next round and may not have retained the first-round messages needed to respond to that request.

This is analogous to DAP-02's `POST /aggregate` with an `AggregateContinueReq`.

###### Context for the `round` field

The `round` field is needed so that the leader can recover from a response being lost. Suppose a many round VDAF is being executed, and that the leader does `PUT /tasks/{task-id}/aggregate_jobs` and that request succeeds, so the helper responds with its first-round prepare messages, and advances its own preparation state to round 1 for the relevant reports. Then, the leader does `POST {aggregation-job-uri}` with the first-round broadcast prepare message, but the helper's response (its second-round prepare messages) gets lost during network transit.

The leader will now re-send `POST {aggregation-job-uri}` with the first-round broadcast prepare messages, and the helper has to decide: are these the first-round broadcast prepare messages (in which case the helper should respond with the previously computed second-round prepare messages) OR are these the second-round broadcast prepare messages (in which case the helper should compute its third-round prepare messages and respond with those)?

In DAP-02, there's no way for the helper to know what to do here unless it retains a full transcript of the prepare protocol so it can match the leader request against a previously seen state. Adding a `round` field to the `AggregateJob` message enables the helper to figure out how to respond to repeated `POST` requests to the same aggregation job.

##### DELETE

Instructs the helper to abandon the aggregate job and allows it to discard all state related to it.

Requiring this would solve https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/241

### Aggregate shares

Only the helper supports this resource.

#### Path

`/tasks/{task-id}/aggregate_shares`

##### PUT

PUT to the aggregate shares resource is how the leader instructs the helper to compute an aggregate share. The request is an idempotent PUT, because if an aggregate share for the parameters in the request already exists, its representation can be returned by the helper without further state mutation.

The body of the request is an `AggregateShareReq`:

```
struct {
  QueryType query_type;
  select (BatchSelector.query_type) {
    case time_interval: Interval batch_interval;
    case fixed_size: BatchID batch_id;
  };
} BatchSelector;

struct {
  BatchSelector batch_selector;
  opaque agg_param<0..2^16-1>;
  uint64 report_count;
  opaque checksum[32];
} AggregateShareReq;
```

If successful, the response from the helper is a redirect to a URI for the aggregate share. See "An aggregate share" resource for discussion.

If the task has expired, or if for some other reason the helper has discarded the data needed to compute the aggregate share request, the helper should refuse the request.

Note that contrary to the report resource, which has an ID assigned by the client respectively, there's no aggregate share ID in the resource. This is because the `batch_selector` and `agg_param` in `struct AggregateShareReq` already uniquely identify a batch (recall that `current-batch` cannot occur in `AggregateShareReq`; a real batch ID is always provided). So a further unique ID is not needed, and would introduce ambiguities: what if a leader referred to an existing aggregate share ID, but with a different `agg_param` or `batch_selector`?

This is analogous to DAP-02's `POST /aggregate_share`.

###### Alternatives: return the struct AggregateShare from `PUT /tasks/{task-id}/aggregate_shares`

In DAP-02, the helper's `/aggregate_share` endpoint is expected to synchronously return the aggregate share. In this API, `PUT /tasks/{task-id}/aggregate_shares` instead yields an aggregate share URI which may then be polled.

The pros of this approach:
- enables asynchronous handling of helper aggregate share computation, since that could take a while if aggregation jobs are pending
- makes the helper's aggregate share handling look more like the leader's collection handling
- the URI for an aggregate share is a nice place to define the DELETE verb

The cons of the this approach:
- It's more API surface for implementations to deal with
- It forces an extra leader->helper request/response in the case where the aggregate share is ready right away, because the leader has to PUT to get a collection URI and then GET that collection URI

An alternative to this design would be to handle this similarly to how DAP-02 does it. `PUT /tasks/{task-id}/aggregate_shares` could instead return `struct AggregateShare` on success. To delete an aggregate share, leader would send `DELETE /tasks/{task-id}/aggregate_shares` with an `AggregateShareReq` in the body. The `BatchSelector` and `agg_param` uniquely identify an aggregate share, so the helper can use those values to decide what data to delete.

### An aggregate share

Only the helper supports this resource.

#### Path

Implementation defined (see `PUT` on the aggregate shares resource)

#### Representation

```
struct {
  HpkeCiphertext encrypted_aggregate_share;
} AggregateShare;
```

#### Required HTTP methods

##### GET/HEAD

If the aggregate share is available, the result is a `struct AggregateShare`. Otherwise the server can return something like HTTP 202 Accepted to indicate it's not ready yet, or HTTP 404 if no such aggregate share is known to the helper. The server may also return an error if the aggregate share was discarded in response to a `DELETE` request on the resource, the task expiring or some other garbage collection policy implemented by the server.

##### DELETE

Instructs the helper to abandon the aggregate share and allows the helper to discard all state related to it. This is akin to DELETE on a collection for the leader.

### Collections

Only the leader supports this resource

#### Path

`/tasks/{task-id}/collections`

#### Required HTTP methods

##### PUT

PUT to the collections resource is how the collector instructs the leader to assemble the aggregate shares. The request is an idempotent PUT, because if a collection corresponding to the provided `Query` and aggregation parameter already exists, its representation can be returned by the helper without further state mutation.

The request body is a `CollectReq`:

```
struct {
  QueryType query_type;
  select (Query.query_type) {
    case time_interval: Interval batch_interval;
    case fixed_size: Empty;
  }
} Query;

struct {
  Query query;
  opaque agg_param<0..2^16-1>; /* VDAF aggregation parameter */
} CollectReq;
```

If successful, the response from the helper is a redirect to a URI for the collection. See "A collection" resource for discussion.

Similarly to the aggregate share resource, there's no collection ID chosen by the collector. This is because a collection is already uniquely identified by the aggregation parameter and the query, making a unique collection ID redundant.

This is analogous to DAP-02's `POST /collect`.

### A collection

Only the leader supports this resource.

#### Path

Implementation defined (see `PUT` on the collections resource)

This resource is analogous to the collect URI in DAP-02.

#### Representation

```
struct {
  PartialBatchSelector part_batch_selector;
  uint64 report_count;
  HpkeCiphertext encrypted_agg_shares<1..2^32-1>;
} Collection;
```

#### Required HTTP methods

##### POST

If the collection is available, the response body is a `struct Collection`. Otherwise the server can return something like HTTP 202 Accepted to indicate it's not ready yet, or HTTP 404 if no such collection is known to the server. The server may also return an error if the collection was discarded due to a `DELETE` request on the resource, the task having expired, or some other garbage collection policy implemented by the server.

Even after receiving a `struct Collection`, the collector MAY continue to send `POST` requests to a collect URI and the responses should still be the `struct Collection` (if it is still available and hasn't been garbage collected).

See "Viewing fixed-size batches as a message queue" for discussion.

This is analogous to DAP-02's `GET` on a collect job URI.

##### DELETE

Instructs the leader to abandon the collection and allows the leader to discard all state related to it. This is akin to DELETE on an aggregate share for the helper (indeed, the leader might send a DELETE to the helper's aggregate share resource after its corresponding collection is deleted).

This is analogous to DAP-02's `DELETE` on a collect job URI.

### Viewing fixed-size batches as a message queue

For tasks that use time interval queries, the collection sub-protocol is driven by the collector. It knows what time intervals it cares about and it sends the queries that then cause the leader and helper to construct aggregate shares.

But fixed-size query batches are fundamentally different: it's the leader that decides what reports belong to which batch and then makes those batches available to the collector. The leader _produces_ batches (by assigning reports to batch IDs), and the collector _consumes_ them (by providing an aggregation parameter and then receiving the collection computed using that aggregation parameter). Further, the leader maintains some state about the stream of batches so that it can respond to `current-batch` queries. This could be a cursor into an ordered stream of batches (it is up to the leader to decide how to order them) or the leader could maintain a set of never-yet-collected batches that are eligible to be "current".

I think the right way to think about the stream of batches being delivered from the leader to the collector is the publisher/subscriber design pattern. The stream of batches created by the leader is a message queue with an at-least-once delivery guarantee. Note that popular message queues don't guarantee in-order message delivery; you have to pay Amazon extra for a FIFO queue. Fixed-size DAP does not require that batches be delivered in order, but the protocol does need to make it possible for implementations to provide an at-least-once delivery guarantee.

The way that message queue systems like Google PubSub or AWS SNS/SQS provide the at-least-once guarantee is that the producer does not consider a message to have been delivered until the consumer explicitly acknowledges receipt. This accounts for the scenario where the consumer crashes while handling the message. If the producer delivers a message to a consumer and does not get an ack within some delay, it can assume the consumer failed somehow and the producer will redeliver the message the next time a consumer reads from the queue.

The guarantee is at-least-once and _not_ exactly-once. Exactly-once delivery guarantees are too difficult to achieve to be considered for DAP.

In the fixed-size query DAP API, `PUT /tasks/{task-id}/collections` where the `CollectReq` asks for `current-batch` is akin to pulling a message from a message queue: the leader will find an undelivered batch, construct a collection URI and give that to the collector.

The eventual collector request to `POST {collect-uri}` is akin to acknowledging a message in a message queue: the collector is implying that it has durably persisted the collect URI, and so now the leader can safely remove the batch from those considered eligible to be "current".

This last point is why the request to the collect URI is a `POST` and not a `GET`. `GET` must be idempotent, but we just saw how a `POST {collect-uri}` can have the side effect of changing what response a client would get from `PUT /tasks/{task-id}/collections`. Thus we need a non-idempotent `POST`.

Using a `POST` here is awkward for the time-interval case, where `GET` would be much more natural, and in particular would make it easier to cache responses. This mild awkwardness is a consequence of our desire to capture both fixed-size and time interval query semantics in a single API.

We could choose to make the two behave differently. Perhaps a collection resource could also support the `GET` method, but only if the relevant task uses time-interval. A `GET` request on a collection resource in a fixed-size task would yield HTTP 405 Method Not Allowed. The tradeoff is additional API surface, and implementations will need extra code specific to one or another query mode.
