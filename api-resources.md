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

The response body is a `struct HpkeConfig` representing the `hpke_config`.

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

Idempotent upload of a report to an aggregator. The request body is a `struct Report`.

This is analogous to DAP-02's `POST /upload`.

### An aggregation job

Only the helper supports this resource.

#### Path

`/tasks/{task-id}/aggregation_jobs/{aggregation-job-id}`

`aggregation-job-id` uniquely identifies an aggregation job. It is chosen by the leader when it dispatches a job to the helper.

#### Representation

```
enum {
  continued(0),
  finished(1),
  failed(2),
  (255),
} PrepareStepState;

struct {
  ReportID report_id;
  PrepareStepState prepare_step_state;
  select (PrepareStep.prepare_step_state) {
    case continued: opaque prep_msg<0..2^32-1>; /* VDAF preparation message */
    case finished: Empty;
    case failed: ReportShareError;
  }
} PrepareStep;

struct {
  u16 round;
  PrepareStep prepare_steps<1..2^32-1>;
} AggregateJob
```

See "POST", below, for explanation and justification of the `round` field.

#### Required HTTP methods

##### GET/HEAD

The response body is a `struct AggregateJob` representing the current state of the reports in the job.

##### PUT

PUT to an aggregate job is how the leader creates an aggregate job in the helper. The body is an `AggregateJobPutReq`:

```
struct {
  ReportMetadata metadata;
  opaque public_share<0..2^32-1>;
  HpkeCiphertext encrypted_input_share;
} ReportShare;

struct {
  QueryType query_type;
  select (PartialBatchSelector.query_type) {
    case time_interval: Empty;
    case fixed_size: BatchID batch_id;
  };
} PartialBatchSelector;

struct {
  opaque agg_param<0..2^16-1>;
  PartialBatchSelector part_batch_selector;
  ReportShare report_shares<1..2^32-1>;
} AggregateJobPutReq;
```

If successful, the helper's response is a `struct AggregateJob` where `prepare_steps` contains the helper's first-round VDAF prepare messages for the report shares in `AggregateJobPutReq`, or errors if `vdaf.prepare` failed for any report.

This is analogous to DAP-02's `POST /aggregate` with an `AggregateInitReq`.

This request is idempotent, so if a helper receives multiple PUT requests for some aggregation job and the members of `AggregateJobPutReq` don't change, the helper can return 200 OK.

The idea here is that all the values in `struct AggregateJobPutReq` never need to be transmitted again during the handling of an aggregate job, which is why the message is not `struct AggregateJob`.

##### POST

POST to an aggregate job is how the leader steps an aggregate job. The request body is a `struct AggregateJob` where `prepare_steps` contains the leader's current-round prepare messages, and `round` is the number of the current round. The response is a `struct AggregateJob` where `prepare_steps` contains the helper's next-round prepare messages. The response's `round` field will be one more than the request's `round`.

We use a POST here because this request is _not_ idempotent. Suppose the leader sends `POST /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` where the body has `round = 1`, and that this is successfully handled by the helper. Besides generating the response, this will have the side effect of advancing the state in the helper to round 2. If the leader were to resend the `POST /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` with `round = 1`, then the request should be rejected by the helper, because it has advanced to the next round.

This is analogous to DAP-02's `POST /aggregate` with an `AggregateContinueReq`.

###### Context for the `round` field

The `round` field is needed so that the leader can recover from a response being lost. Suppose a 2-round VDAF is being executed, and that the leader does `PUT /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` and that request succeeds, so the helper responds with its first-round prepare messages. Then, the leader does `POST /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` with the first-round broadcast prepare message, but the helper's response gets lost during network transit.

If the helper received the `POST` and advanced its state to the second round, then the leader should do `GET /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` so it can compute the second round broadcast message and then do `POST /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}` to have the helper move to the finished state. If the helper did not receive the `POST`, then the leader should re-send the first-round broadcast prepare message.

But in DAP-02, the leader has no way to know what happened in the helper, leaving it unable to recover from this state. Adding a `round` field to the `AggregateJob` message enables the leader to reliably and idempotently find out what state the helper is in by doing `GET /tasks/{task-id}/aggregate_jobs/{aggregation-job-id}`, and then taking the appropriate next step.

##### DELETE

Instructs the helper to abandon the aggregate job and allows it to discard all state related to it.

Requiring this would solve https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/241

### An aggregate share

Only the helper supports this resource.

#### Path

`/tasks/{task-id}/aggregate_shares/{aggregate-share-id}`

`aggregate-share-id` uniquely identifies an aggregate share. It is chosen by the leader when it requests an aggregate share by the helper.

#### Representation

```
struct {
  HpkeCiphertext encrypted_aggregate_share;
} AggregateShare;
```

#### Required HTTP methods

##### GET/HEAD

If the aggregate share is available, the result is a `struct AggregateShare`. Otherwise the server can return something like HTTP 202 Accepted to indicate it's not ready yet, or HTTP 404 if no such aggregate share is known to the helper.

##### PUT

PUT to an aggregate share resource is how the leader instructs the helper to compute aggregate shares. The request is an idempotent PUT, because if an aggregate share with the provided ID already exists, its representation can be returned by the helper without further state mutation.

The body of the request is an `AggregateShareReq`:

```
struct {
  QueryType query_type;
  select (BatchSelector.query_type) {
    case time_interval: Interval batch_interval;
    case fixed_size: Empty;
  };
} BatchSelector;

struct {
  BatchSelector batch_selector;
  opaque agg_param<0..2^16-1>;
  uint64 report_count;
  opaque checksum[32];
} AggregateShareReq;
```

If successful, the response from the helper is a `struct AggregateShare`. That same share may later be obtained by a GET request on the resource.

This is analogous to DAP-02's `POST /aggregate_share`.

###### A note on `BatchSelector.fixed_size`

In DAP-02, a `BatchSelector` with `query_type = fixed_size` contains a `BatchID`. In this API, the batch ID hoisted up into the resource URI. This implies that `time_interval`-type queries now also have a batch ID, chosen by the leader. While aggregate shares will often (always?) be 1:1 with collections, the IDs do not have to match.

TODO: timg to read more about chunky DAP and think about how it intersects with this proposal, especially https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/342

##### DELETE

Instructs the helper to abandon the aggregate share and allows the helper to discard all state related to it. This is akin to DELETE on a collection for the leader.

### A collection

Only the leader supports this resource.

#### Path

`/tasks/{task-id}/collections/{collection-id}`

`collection-id` uniquely identifies a collection. It is chosen by the collector when it POSTs to the resource.

#### Representation

```
struct {
  PartialBatchSelector part_batch_selector;
  uint64 report_count;
  HpkeCiphertext encrypted_agg_shares<1..2^32-1>;
} Collection;
```

#### Required HTTP methods

##### GET/HEAD

If the collection is available, the response body is a `struct Collection`. Otherwise the server can return something like HTTP 202 Accepted to indicate it's not ready yet, or HTTP 404 if no such aggregate share request is known to the server.

This is analogous to DAP-02's `GET` on a collect job URI.

##### PUT

PUT to a collection resource is how the collector instructs the leader to assemble the aggregate shares. The request is an idempotent PUT, because if a collection with the provided ID already exists, its representation can be returned by the helper without further state mutation.

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

If successful, the response from the helper is a `struct Collection`. That same share may later be obtained by a GET request on the resource.

This is analogous to DAP-02's `POST /collect`.

###### A note on `Query.fixed_size`

`struct Query` is essentially identical to `struct BatchSelector`, so the note about `BatchSelector.fixed_size` from `PUT aggregate_share` applies here, except that a collection's ID is chosen by the collector.

##### DELETE

Instructs the leader to abandon the collection and allows the leader to discard all state related to it. This is akin to DELETE on an aggregate share for the helper (indeed, the leader might send a DELETE to the helper's aggregate share resource after its corresponding collection is deleted).

This is analogous to DAP-02's `DELETE` on a collect job URI.

#### Alternatives: `collection-id`, `PUT` vs. `POST` and idempotence?

This proposal introduces the notion of a `collection-id`, which is chosen by the collector when it sends `CollectReq` to helper. In DAP-02, a collection is already uniquely identified by the combination of the aggregation parameter and the query, meaning we can get by without `collection-id`. Let's sketch out what the API would look like so we can weigh pros and cons.

`POST /tasks/{task-id}/collections`

The body is a `CollectReq`, defined as above. The request method is `POST` instead of `PUT` because I don't think this request can be idempotent. Let's say a collector makes a time interval query over some interval _i_ and it is received by the leader at time _t1_. At _t1_, the leader has _n1_ reports that fall into the interval _i_. Then, suppose at least one more report that falls into _i_ arrives and the leader and helper prepare it. Then, at _t2 > t1_, the collector sends a query with the same interval _i_ again.

Should the leader serve up the results it computed at time _t1_? Or should it make a new collection, consuming another unit of max batch query, that includes the reports that arrived and were prepared between _t1_ and _t2_?

If collections are identified by `collection-id`, then there's no ambiguity: the collector can poll `GET /tasks/{task-id}/collections/{collection-id}` to obtain the same collection over and over again. `PUT /tasks/{task-id}/collections/{collection-id}` with the same `collection-id` is also unambiguous, and if the collector wants to make a new query with the same interval, it can choose a new `collection-id` and `PUT` that, which the leader will service if the task's parameters allow it.

The cons of `collection-id` is that an aggregation parameter and a `struct Query` don't uniquely identify a collection. So if a collector wants to find out if there's an existing collect job that meets its parameter, it has to enumerate all of them using `GET /tasks/{task-id}/collections`. We could improve this either with [HTTP QUERY](https://www.ietf.org/archive/id/draft-ietf-httpbis-safe-method-w-body-02.html) or query params on `GET /tasks/{task-id}/collections`.
