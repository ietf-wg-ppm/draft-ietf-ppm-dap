# Error handling

A protocol participant *aborts* the protocol by tearing down the connection with
its peer.

An *alert* is a message sent either in an HTTP request or response that signals
to the receiver that the peer has aborted the protocol. The payload is

```
struct {
  PATask task;
  opaque payload<0..255>;
} PAAlert;
```

where `task` is the associated PA task (this value is always known) and
`payload` is the message. When sent by an aggregator in response to an HTTP
request, the response status is [TODO]. When sent in a request to an
aggregator, the URL is always `[aggregator]/error`, where `[aggregator]` is the
URL of the aggregator endpoint.

## Common abort conditions

The following specify the "boiler-plate" behavior for various error conditions.

- The message type for the payload of each request and response is unique for
  each URL. If ever a client, aggregator, or collector receives a request or
  response to a request with a malformed payload, then the receiver aborts and
  alerts the peer with "unrecognized message".

- Each POST request to an aggregator contains a `PATask`. If the aggregator does not
  recognize the task, i.e., it can't find a `PAParam` for which `PATask.id ==
  PAParam.task.id`, then it aborts and alerts the peer with "unrecognized task".
