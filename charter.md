There are many situations in which it is desirable to take measurements of data
which people consider sensitive. For instance, a browser company might want to
measure web sites that do not render properly without learning which users visit
those sites, or a public health authority might want to measure exposure to some
disease without learning the identities of those exposed. In these cases, the
entity taking the measurement is not interested in people's individual responses
but rather in aggregated data (e.g., how many users had errors on site X).
Conventional methods require collecting individual measurements in plaintext and
then aggregating them, thus representing a threat to user privacy and rendering
many such measurements difficult and impractical.

New cryptographic techniques address this gap through a variety of techniques,
all of which aim to ensure that the server (or multiple, non-colluding servers)
can compute the aggregated value without learning the value of individual
measurements. The Privacy Preserving Measurement (PPM) work will
standardize protocols for deployment of these techniques on the Internet. This
will include mechanisms for:

- Client submission of individual measurements, potentially along with proofs of
  validity
- Verification of validity proofs by the server(s), if sent by client
- Computation of aggregate values by the server(s) and reporting of results to
  the entity taking the measurement

A successful PPM system assumes that clients and servers are configured with
each other's identities and details of the types of measurements to be taken.
This is assumed to happen out of band and will not be standardized in this
working group.

The WG will deliver one or more protocols which can accommodate multiple PPM
algorithms. The initial deliverables will support the calculation of simple
predefined statistical aggregates such as averages, as well as calculations of
the values that most frequently appear in individual measurements. The PPM
protocols will use cryptographic algorithms defined by the CFRG. The protocol
will be designed to limit abuse by both client and aggregators, including
exposure of individual user measurements and denial of service attacks on the
measurement system. The resulting documents shall clearly describe abuse cases
and remaining attacks which are not prevented or mitigated by the protocol.

The starting point for PPM WG discussions shall be draft-ietf-ppm-dap.
