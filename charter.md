There are many situations in which it is desirable to take
measurements of data which people consider sensitive. For instance,
one might want to measure the most common sites that people browse to
or exposure to some disease. In these cases, the entity taking the
measurement is not interested in people's individual responses but
rather in aggregated data (e.g., how many users visit URL X), but
conventional methods require collecting individual responses and then
aggregating them, thus representing a threat to user privacy and
rendering many such measurements difficult and impractical.

New cryptographic techniques e.g., Prio address this gap by splitting
up measurements between multiple servers which can jointly compute the
aggregate value without either server learning the value of individual
responses. The Private Data Aggregation (PDA) work will standardize
techniques for deployment of these techniques on the Internet. This
will include mechanisms for:
         
- Client submission of individual reports, including proofs of validity.
- Verification of validity proofs by the servers
- Computation of aggregate values by the servers and reporting of
  results to the entity taking the measurement
  
Configuration of clients and servers is out of scope for the working
group. It is assumed that this happens out of band as part of the
PDA service. 

The WG will deliver one or protocols which can accommodate multiple
PDA algorithms, with the initial deliverable supporting both simple
predefined aggregates and measurement of "heavy hitters" out of the
set of arbitrary strings submitted by users.  The PDA WG will not
itself define cryptographic algorithms for PDA but will instead use
algorithms defined by the CFRG.

The starting point for PDA WG discussions shall be [TODO].










            
