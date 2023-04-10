'''
Compare the network time consumed by an aggregation job for DAP-04 versus PR #393:
https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/pull/393

We approximate the network time as the roundtrip latency plus the amount of
data sent divied by the bandwidth of the network.

We expect the network time to differ as a result of (1) changing the number of
HTTP requests and (2) changing the number of bytes uploaded versus downloaded.
This is the case if the bandwidth over the connection is not symmetric, as is
often the case. Note however that the total number of bytes transmitted does
not change significantly.

We make the following assumptions about the task configuration:
* The Helper uses HPKE ciphersuite (X25519, HKDF-SHA256, AES-GCM).
* The query type is "time_interval".
* No report in the aggregation job is rejected (0% error rate).
'''
from math import ceil, sqrt

# Bumber of reports are included in the aggregation job.
REPORTS_PER_AGG_JOB = 1000

# Leader->Helper upload speed (megabits/s)
UPLOAD_MBPS = 50

# Leader->Helper download speed (megabits/s)
DOWNLOAD_MBPS = 100

# Total roundtrip latency in seconds of an HTTP request and response.
ROUNDTRIP_S = 0.100

def bytes_per_report_share(bytes_per_public_share, bytes_per_input_share):
    '''Number of bytes per report share.'''
    n = 16 # report_id
    n += 8 # time
    n += 4 + bytes_per_public_share # public_share
    n += 1 # HpkeConfig.config_id
    n += 2 + 32 # HpkeConfig.enc (X25519 key share)
    n += 4 + bytes_per_input_share + 16 # HpkeConfig.payload
    return n

def agg_job_network_time_draft04(
            reports_per_agg_job,
            bytes_per_agg_param,
            bytes_per_public_share,
            bytes_per_helper_input_share,
            bytes_per_prep_share_vec,
            bytes_per_prep_vec,
            upload_mbps,
            download_mbps,
            roundtrip_s
        ):
    '''
    Estimation of the network time required to run a DAP-04 aggregation job
    with the given parameters and network characteristics. The return value is
    the number of seconds.
    '''
    upload_bytes = 0
    download_bytes = 0
    round_trips = 0

    # AggregationJobInitReq
    upload_bytes += 4 + bytes_per_agg_param # agg_param
    upload_bytes += 1 # PartialBatchSelector.query_type == "time_interval"
    upload_bytes += 4 + reports_per_agg_job * \
            bytes_per_report_share(bytes_per_public_share,
                                   bytes_per_helper_input_share)

    # Preparation
    for (bytes_per_prep_share, bytes_per_prep) in \
            zip(bytes_per_prep_share_vec, bytes_per_prep_vec):
        # AggregationJobResp
        download_bytes += 4 + (16 + 1 + 4 + bytes_per_prep_share) * \
                reports_per_agg_job
        round_trips += 1

        # AggregationJobContinueReq
        upload_bytes += 2 # round
        upload_bytes += 4 + (16 + 1 + 4 + bytes_per_prep) * \
                reports_per_agg_job

    # AggregationJobResp
    download_bytes += 4 + (16 + 1) * \
            reports_per_agg_job
    round_trips += 1

    # Convert to megabits
    upload_mb = upload_bytes * 8 / 1000000
    download_mb = download_bytes * 8 / 1000000

    return round_trips * roundtrip_s + \
            upload_mb / upload_mbps + \
            download_mb / download_mbps

def agg_job_network_time_pr393(
            reports_per_agg_job,
            bytes_per_agg_param,
            bytes_per_public_share,
            bytes_per_helper_input_share,
            bytes_per_prep_share_vec,
            bytes_per_prep_vec,
            upload_mbps,
            download_mbps,
            roundtrip_s,
        ):
    '''
    Estimation of the network time required to run a DAP+PR#393 aggregation job
    with the given parameters and network characteristics. The return value is
    the number of seconds.
    '''
    upload_bytes = 0
    download_bytes = 0

    # Compute the number of round trips. In the first round trip, the Leader
    # sends its prep share 1 and the Helper replies with prep message 1 and its
    # prep share 2; in the second round trip, the Leader sends prep message 2
    # and its prep share 3; and so on.
    rounds = len(bytes_per_prep_vec)
    round_trips = ceil((rounds + 1) / 2)

    # AggregationJobInitReq
    upload_bytes += 4 + bytes_per_agg_param # agg_param
    upload_bytes += 1 # PartialBatchSelector.query_type == "time_interval"
    upload_bytes += 4 + reports_per_agg_job * \
            bytes_per_report_share(bytes_per_public_share,
                                   bytes_per_helper_input_share)

    # Compute the total number of bytes uploaded and downloaded during
    # preparation.
    round_num = 1
    for (bytes_per_prep_share, bytes_per_prep) in \
            zip(bytes_per_prep_share_vec, bytes_per_prep_vec):
        prep_share_bytes = 4 + (16 + 1 + 4 + bytes_per_prep_share) * \
                reports_per_agg_job
        if round_num % 1 == 1: # Leader sends prep share
            upload_bytes += prep_share_bytes
        else: # Helper sends prep share
            download_bytes += prep_share_bytes

        prep_bytes = 4 + (16 + 1 + 4 + bytes_per_prep) * \
                reports_per_agg_job
        if round_num % 1 == 1: # Helper sends prep message
            download_bytes += prep_bytes
        else: # Leader sends prep message
            upload_bytes += prep_bytes

        round_num += 1

    # Tack on the 2-byte round indicator for each AggregationJobContinueReq.
    upload_bytes += 2 * (round_trips - 1)

    # Convert to megabits
    upload_mb = upload_bytes * 8 / 1000000
    download_mb = download_bytes * 8 / 1000000

    return round_trips * roundtrip_s + \
            upload_mb / upload_mbps + \
            download_mb / download_mbps

'''
Prio3Count
'''

print('DAP-04/Prio3Count {0:.3g}s'.format(agg_job_network_time_draft04(
    REPORTS_PER_AGG_JOB,
    0, # bytes_per_agg_param
    0, # bytes_per_public_share
    16 * 2, # bytes_per_helper_input_share
    [4 * 8],
    [0], # bytes_per_prep
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

print('PR#393/Prio3Count {0:.3g}s'.format(agg_job_network_time_pr393(
    REPORTS_PER_AGG_JOB,
    0, # bytes_per_agg_param
    0, # bytes_per_public_share
    16 * 2, # bytes_per_helper_input_share
    [4 * 8],
    [0], # bytes_per_prep
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

'''
Prio3Sum/Histogram
'''

bytes_per_prio3_sum_or_histogram_verifier_share = 3 * 16

print('DAP-04/Prio3Sum/Histogram {0:.3g}s'.format(agg_job_network_time_draft04(
    REPORTS_PER_AGG_JOB,
    0,      # bytes_per_agg_param
    16 * 2, # bytes_per_public_share
    16 * 3, # bytes_per_helper_input_share
    [bytes_per_prio3_sum_or_histogram_verifier_share],
    [16], # bytes_per_prep
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

print('PR#393/Prio3Sum/Histogram {0:.3g}s'.format(agg_job_network_time_pr393(
    REPORTS_PER_AGG_JOB,
    0,      # bytes_per_agg_param
    16 * 2, # bytes_per_public_share
    16 * 3, # bytes_per_helper_input_share
    [bytes_per_prio3_sum_or_histogram_verifier_share],
    [16], # bytes_per_prep
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

'''
Prio3SumVec, a VDAF used to aggregate a vector of integers in a given range:
https://docs.rs/prio/latest/prio/vdaf/prio3/type.Prio3SumVec.html
'''

def bytes_per_prio3_sum_vec_verifier_share(bit_len, vec_len):
    '''Number of bytes per verifier share for Prio3SumVec.'''
    flattened_len = bit_len * vec_len

    # The output of the validity circuit is the sum of the gadget applied to
    # different chunks of the input, which is `bit_len * vec_len` field
    # elements. The optimal chunk size is the square root of the input length.
    chunk_len = max(1, int(sqrt(flattened_len)))

    # The number of times the gadget is called.
    gadget_calls = int(flattened_len / chunk_len)
    if flattened_len % chunk_len > 0:
        # The last chunk is padded to `chunk_len`.
        gadget_calls += 1

    verifier_len = 1 # Share of the circuit output
    verifier_len += 1 # Ootput of gadget polynomial evaluation
    verifier_len += 2 * gadget_calls # Arity of the gadget

    n = 16 # joint randomness part
    n += verifier_len * 16 # verifier share
    return n

# VDAF parameters
bit_len = 16
vec_len = 1000

print('DAP-04/Prio3SumVec {0:.3g}s'.format(agg_job_network_time_draft04(
    REPORTS_PER_AGG_JOB,
    0,      # bytes_per_agg_param
    16 * 2, # bytes_per_public_share
    16 * 3, # bytes_per_helper_input_share
    [bytes_per_prio3_sum_vec_verifier_share(bit_len, vec_len)],
    [16], # bytes_per_prep
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

print('PR#393/Prio3SumVec {0:.3g}s'.format(agg_job_network_time_pr393(
    REPORTS_PER_AGG_JOB,
    0,      # bytes_per_agg_param
    16 * 2, # bytes_per_public_share
    16 * 3, # bytes_per_helper_input_share
    [bytes_per_prio3_sum_vec_verifier_share(bit_len, vec_len)],
    [16], # bytes_per_prep
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

'''
Poplar1

NOTE: The size of the public and input share sent from the Leader and Helper
makes up the vast majority of the upload cost. With some protocol changes, we
should be able to amortize this cost over multiple aggregation jobs involving
the same report. See
https://github.com/ietf-wg-ppm/draft-ietf-ppm-dap/issues/409
'''

def bytes_per_poplar1_public_share(bit_len):
    '''Size of the Poplar1 public share.'''
    n = int((bit_len + 7) / 8) # packed control bits
    n += 16 * bit_len # seeds
    n += 2 * 8 * (bit_len - 1) # correction words for inner nodes
    n += 2 * 32 # correction word for leaf nodes
    return n

def bytes_per_poplar1_input_share(bit_len):
    '''Size of the Poplar1 input share.'''
    n = 16 # IDPF key
    n += 16 # Seed for correlated randomness
    n += 3 * 8 * (bit_len - 1) # correlated offsets (inner nodes)
    n += 3 * 32 # correlated offsets (leaf nodes)
    return n

def bytes_per_poplar1_sketch(is_leaf):
    return 3 * 32 if is_leaf else 3 * 8

def bytes_per_poplar1_sketch_verifier_share(is_leaf):
    return 32 if is_leaf else 8

# VDAF parameters
bit_len = 256
is_leaf = True # Wether the candidate prefixes are at the leaves of the IDPF tree
# Size of the encoded sequence of candidate prefixes. Estimated from libprio-rs' microbenchmarks:
# https://github.com/divviup/libprio-rs/blob/main/benches/speed_tests.rs#L414
bytes_per_agg_param = 1600

print('DAP-04/Poplar1 {0:.3g}s'.format(agg_job_network_time_draft04(
    REPORTS_PER_AGG_JOB,
    bytes_per_agg_param,
    bytes_per_poplar1_public_share(bit_len),
    bytes_per_poplar1_input_share(bit_len),
    [
        # Sketch share is the same length as the sketch.
        bytes_per_poplar1_sketch(is_leaf),
        bytes_per_poplar1_sketch_verifier_share(is_leaf),
    ],
    [
        bytes_per_poplar1_sketch(is_leaf),
        0,
    ],
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

print('PR#393/Poplar1 {0:.3g}s'.format(agg_job_network_time_pr393(
    REPORTS_PER_AGG_JOB,
    bytes_per_agg_param,
    bytes_per_poplar1_public_share(bit_len),
    bytes_per_poplar1_input_share(bit_len),
    [
        # Sketch share is the same length as the sketch.
        bytes_per_poplar1_sketch(is_leaf),
        bytes_per_poplar1_sketch_verifier_share(is_leaf),
    ],
    [
        bytes_per_poplar1_sketch(is_leaf),
        0,
    ],
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

'''
Hypothetical VDAF with 10 rounds
'''

print('DAP-04/FakeVdaf {0:.3g}s'.format(agg_job_network_time_draft04(
    REPORTS_PER_AGG_JOB,
    0,    # bytes_per_agg_param
    100, # bytes_per_public_share
    100, # bytes_per_input_share
    [ 100 for i in range(10) ],
    [ 100 for i in range(10) ],
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))

print('PR#393/FakeVdaf {0:.3g}s'.format(agg_job_network_time_pr393(
    REPORTS_PER_AGG_JOB,
    0,   # bytes_per_agg_param
    100, # bytes_per_public_share
    100, # bytes_per_input_share
    [ 100 for i in range(10) ],
    [ 100 for i in range(10) ],
    UPLOAD_MBPS,
    DOWNLOAD_MBPS,
    ROUNDTRIP_S,
)))
