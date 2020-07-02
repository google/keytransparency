# Key Transparency New Design

## Objective

Key Transparency currently suffers from a design-space trade-off in two dimensions between
low latency key updates and verification bandwidth; each snapshot of the
key-value Merkle tree creates an additional point in time that clients must
audit when inspecting their account history.
Using Key Transparency 1.0 and below requires the presence of powerful
auditors who can verify that no information has been lost or tampered with between all snapshots.

| Update Latency | History Audit `O(T * log N)`  | Key Lookup |
|----------------|------------------|-------------|
| hr             | 45 Kb/day         | ~2Kb       |
| min            | 2.7 Mb/day        | ~2Kb       |
| s              | 160 Mb/day        | ~2Kb       |

Table: *Based on 1B users, updating 200 keys per second*

Key Transparency 2.0 is a new set of algorithms that removes this fundamental
trade-off by sharing the task of auditing between pairs of clients. As a
result, all configurations have efficiently auditable data structures that do
not require the presence of 3rd party auditors.

We expect that many applications will want to prioritize lower latency and
reliability by using a *trust, then verify* mode whereby clients receive key
updates that they can later verify as being part of the global, consistent
state.  However, this does not preclude individual clients that have a lower
tolerance for risk from waiting for full, globally consistent verification
before using fresh public keys from their peers.

| Update Latency | History Audit `O(log T * log N)` | Key Lookup |
|----------------|------------------|------------|
| hr             | 18Kb             | ~2Kb       |
| min            | 30Kb             | ~2Kb       |
| s              | 40Kb             | ~2Kb       |


## Verifiable Data Structures

### Gossip Network
The job of the gossip network is to ensure that there is a single, globally consistent, lineage of log roots.

The exact solution is TBD. 

### Log of Map Roots

The log server contains a list of map roots representing sequential snapshots of a key-value directory.

Log servers offer the following API:

1. Latest Signed Log Root
1. Get consistency proof between log size a and b.
1. Get log item i with inclusion proof to log size a.

### Map Root Snapshots
Each Map Root represents a snapshot of a key-value dictionary.
The map is implemented as a sparse Merkle tree.

* Indexes in the map are randomized and privacy protected via a Verifiable Random Function.
* Values in the map represent the full history of values that have ever been
  stored at this index. This is accomplished by storing the Merkle root of a mini log of these values.

The map offers the following API:

1. Get map value at index j with inclusion proof to snapshot a.

### Value History Log
These mini logs store not just the latest value, but also store every previous
value in order.

They are what users query when looking up their own key history, and they are
what their peers verify in order to ensure that no history has been lost.

The value log offers the following API:

1. Get latest value at snapshot z with inclusion proof.
1. Get consistency proof between snapshot roots y and z.
1. Get range of historical values between snapshots y and z.

## Client Verification

Key Transparency clients store:
1. The root of the log of map roots. This ensures that the client is using the
   same snapshots as the rest of the world.
1. The root of every (proven consistent) mini log they have queried. This
   ensures that snapshots represent append-only representations of the world.

When querying, Key Transparency clients ask for proof that the current snapshot
and value are consistent with previous values that the client has observed.

## Efficiency Innovations

Generating append-only proofs for large sparse Merkle trees is not efficient.
An append-only proof between two snapshots containing `M` changes per snapshot
in a map of size `N` over `T` snapshots contains roughly `O(T * M log N)`
hashes.
1. Instead of verifying that the entire map is an append-only operation from
   previous values, we isolate the work of verification to individual
   sub-trees. `O(T * 1 log N)`
1. Rather than verifying every single snapshot, we only verify the snapshots
   that the sender and receiver used. `O(1 * 1 log N)`
1. But the snapshots that the sender and receiver used are unknown, so we use a
   [meet-in-the-middle algorithm](meet-in-the-middle.md) to sample log
   O(log T) revisions in such a way that they intersect. `O(log T * log N)`


# Work Plan

1. Migrate to use Trillian mini logs for user updates.
    1. Switch from `int64` treeIDs to `[]byte` to support deriving the `treeID` from the VRF.
    1. Sequence and sign mini logs synchronously rather than relying on a separate process.
1. Write a batching algorithm to accumulate updates across many mini logs.
1. Write new mini logs roots to the map instead of the current, direct value approach.
1. Update client verification algorithms.
