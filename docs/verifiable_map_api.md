Verifiable Map API
==================
* Get Leaf Data And Inclusion proofs  
```go
Get(index []byte, epoch uint64) (leaf_data []byte, neighbors [][]byte)
```
Returns the value at index along with an inclusion proof through the sparse tree
to the requested epoch.

* Put Mutation 
```go
Put(index, mutation []byte) (SCT, LogProof, STHProof)
```
Queues a mutation for inclusion in a future epoch. (Not guarunteed to be the 
next epoch.) 

For consieration:
- We could tie mutations to the specific epoch they expect to be applied in.
If, due to concurrency they guess wrong, the mutation will fail and can be 
tried again.
- We could tie mutations to an expected hash of the leaf they expect to mutate.
If, due to concurrency they guess wrong, the mutation will fail and can be tried
again. 

The mutation will go in the queue, but it's not guaranteed to go in ahead of
any existing epoch advancement items already in the queue.
We could put the failed mutation in the log so as to get an SCT proof.

The client would only know if the mutation failed if the client could parse
the leaf data and detect that the change had not been applied.




 - Duplicate mutations should be supported as long as they explicitly reference
    the data that they are mutating or the epoch in which they expect to be 
    executed.
 - If two put requests occur for the same epoch, the last one is comitted.
 - Mutations should explicitly refrence any versioned data they mutate. 
   Mutations can fail.
 - Optionally returns an SCT.
 - Returns an inclusion proof to the mutation log and sparse merkle tree once 
   the mutation has been included in an epoch. (Same as the return of GET)


Proxying APIS to ChronLogs
------------
* Consistency proof for the Sparse Treee Heads between two epochs.
* Consistency proof for the Log of Mutations between two epochs.
* SCT proof. Returns mutation log proof and sparse tree proof.

Monitor APIS
------------
*  GetMutations(start, end) ([]mutations)
*  GetSignedSparseTreeHead(epoch) (sth)

Gossip APIS
-------
* Get current signed sparse tree head

