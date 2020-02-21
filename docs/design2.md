# Key Transparency 2.0

## Objective

Key Transparency currently suffers from a design-space tradeoff in two dimensions between
speed and verification bandwidth.  Each snapshot of the key-value Merkle tree creates an additional
point in time that clients must audit when inspecting their account history. 
Using Key Transparency in this mode requires the presence of powerful auditors who can verify
that no information has been lost between all snapshots.

| Update Speed | Trust, then Verifiy | Verify First |
|--------------|---------------------|--------------|
| hr           | Tractable Bandwidth | Unusable     |
| min          |                     | Intractable  |
| s            |                     | Intractable  |


Key Transparency 2.0 is a new set of algorithms that resolves this fundamental tradeoff by sharing 
the task of auditing between pairs of clients. As a result, all configurations result in efficiently
auditable data structures, without the presence of 3rd parties. 

We expect that many applications will want to prioritize speed and reliability by using a trust, then verify mode, but because the client operations are very similar, users could have the option to wait a bit longer in order to have high confidence that they are using data from a snapshot that is widely available. 

| Update Speed | Trust, then Verifiy | Verify First |
|--------------|---------------------|--------------|
| hr           | Tractable Bandwidth | Unusable     |
| min          | Tractable Bandwidth | Opt-in       |
| s            |                     | Tractable    |


## Data Structures

### Gossip Network
The job of the gossip network is to ensure that there is a single, globally consistent lineage of log roots. 
To keep ![n^2](https://render.githubusercontent.com/render/math?math=n%5E2) communication costs low, and to prevent sybil attacks, clients use a small ~20 set of gossip nodes.

Each gossip node fetches the latest signed log root (SLRs) and verifies consistency with all previously seen roots.
After verifying, the gossip node signs the log root.

Gossip nodes offer the following APIs:

1. Get Signed Root 

### Log of Map Roots

The log server collects signatures from the gossip nodes to produce a Signed Log Root that has a quorum of gossip signatures.

The log server contains a list of map roots representing sequential snapshots of a key-value directory.

Log servers offer the following APIs:

1. Latest Signed Log Root
1. Get consistency proof between log size a and b. 
1. Get log item i with inclusion proof to log size a.

### Map Root Snapshots 
Each Map Root represents a snapshot of a key-value dictionary.
The map is implemented as a sparse merkle tree of fixed depth. This should be changed to a patricia-prefix-tri for better efficiency.

* Indexes in the map are randomized and privacy protected via a Verifiable Random Function.
* Values in the map represent the full history of values that have ever been stored at this index. This is accomplished by storing the merkle root of a mini-log of these values.
  
The map offers the following APIs:

1. Get map value at index j with inclusion proof to snapshot a.

### Value History Log
These mini logs store not just the latest value, but also store every previous value in order.

These mini logs are what users query when looking up their own key history, and they are what their peers verify in order to ensure that no history has been lost. 

The value log offers the following API:

1. Get latest value at snapshot z with inclusion proof.
2. Get consistency proof between snapshot roots y and z.
3. Get range of historical values between snaptots y and z.

## Client Verification 

Key Transparency clients store 
1. The root of the log of map roots. This ensures that the client is using the same snapshots as the rest of the world.
1. The root of every mini-log they have queried. This ensures that snapshots represent append-only representations of the world.

When querying, Key Transparency clients ask for proof that the current snapshot and value are consistent with previous values that the client has observed.

## Efficiency Improvements

Generating append-only proofs for large sparse merkle trees is not efficient. For N changes per snapshot in a map of size M over T snapshots is roughly O(T * N log M) 
1. Instead of verifying that the entire map is an append-only operation from previous values, we isolate the work of verification to individual sub-trees. O (T * 1 log M)
1. Rather than verifying every single snapshot, we only verify the snapshots that the sender and receiver used. O(1 * 1 log M)
1. But the snapshots that the sender and reciever used are unknown, so we use a meet-in-the-middle algorithm to sample log T of them. O( log T * log M)


# Work Plan

1. Can Trillian Logs be used as mini logs?
    1. Can we get fast sequencing without master election?
    1. Can we cap the maximum number of elements? Do we need to?
1. Store updates to mini-logs
1. Write a batching algorithm to accumulate updates accross many mini-logs.
1. Write new mini-logs roots to the map instead of the current, direct value approach.
1. Update client verification algorithms.
