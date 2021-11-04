There are many situations in which it is desirable to take
measurements of data which people consider sensitive. For instance,
a browser company might want to measure web sites that do not render properly without learning which users visit those sites, 
or a public health authority might want to measure exposure to some disease without learning the identities of those exposed. In these cases, the entity taking the
measurement is not interested in people's individual responses but
rather in aggregated data (e.g., how many users had errors on site X).
Conventional methods require collecting individual measurements and then
aggregating them, thus representing a threat to user privacy and
rendering many such measurements difficult and impractical.

New cryptographic techniques address this gap by splitting
measurements between multiple, non-colluding servers which can jointly compute the
aggregate value without either server learning the value of individual
measurements. The Privacy Respecting Incorporation of Values (PRIV) work will standardize
protocols for deployment of these techniques on the Internet. This
will include mechanisms for:
         
- Client submission of individual measurements, including proofs of validity
- Verification of validity proofs by the servers
- Computation of aggregate values by the servers and reporting of
  results to the entity taking the measurement

A successful PRIV system assumes that clients and the various servers
are configured with each other's identities and details of the types of
measurements to be taken. This is assumed to happen out of band
and will not be standardized in this working group.

The WG will deliver one or more protocols which can accommodate multiple
PRIV algorithms. The initial deliverables will support the calculation of simple
predefined statistical aggregates such as averages, as well as calculations of the values that most frequently appear in individual measurements.  The PRIV protocols will use
cryptographic algorithms defined by the CFRG.

The starting point for PRIV WG discussions shall be draft-gpew-priv-ppm.










            
