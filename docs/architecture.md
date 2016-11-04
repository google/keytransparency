# Key Transparency Architecture

![Architecture](images/architecture.png)

# Queue
The Queue is the central component of the Key Server.
The Queue gives a definitive, consistent ordering to all changes made to the 
key server data structure.

The Queue is a Multi-Writer, Single Reader data object.
Previous iterations had the Queue as a Multi-Writer, Multi-Reader object, where 
each node would receive the same data, much like the Raft Consesnsus Algorithm. 
In the Single Reader scheme, the queue is keeping track of global state, ie. how 
many items have been processed and added to the database.

The Queue stores mutations that have not been processed by the signer and 
written to the Merkle Tree data structures.

## Queue Atomicity Notes
Mutations in the queue may be deleted from the queue once they have been 
successfully processed by the signer and committed to the leaf database. We do 
not require that an epoch advancement occur before queue entries may be deleted.

Cross-Domain Transactions:
To process an item from the queue, the item is first deleted. If it cannot be
deleted (due to another process dequeueing it first or any other error), the next
item is fetched and processed. Once an item is safely deleted from the queue, it
is processed and the changes are written to the database. If the database commit
fails, all changes are rolled back. The item is not placed back in the queue and
is "lost". However, since clients perform retries until the data they are trying
to update appears in the database, this data loss does not violate the API
contract.

## Queue Epoch Advancement Notes
When advancing epochs, we can't include the expected epoch number because 
multiple epoch advancement requests could be received by the queue out-of-order.

If we assume a single writer case, we could add fancy logic to the Signer such 
that no more than one epoch advancement request is ever present in the  queue at
once. This, however, would require the Signer to know what's in the queue when it
crashes and resumes.

# Signer
The signer processes mutations out of the queue.
In the present configuration, the signer writes each node into the leaf table 
with a version number in the future. If the signer crashes, it simply picks up
processing the queue where it left off. Writing to the same node twice with the 
same data is permitted.

The signer applies the mutations in the queue to the entries contained in 
`current_epoch - 1`. Duplicate mutations processed during the same epoch will 
succeed. Duplicate mutations processed across epochs SHOULD fail. (Each 
mutation should be explicit about the previoius version of data it is modifying.)

To advance to the next epoch, the signer inserts an epoch advancement marker 
into the queue and waits to receive it back on the queue before committing all 
the changes received between epoch markers into a version of the sparse merkle
tree and signing the root node. 

The Signer also takes each item received in the queue and sends it to the 
Log of Mutations, so that Monitors can recreate the tree by just reading the 
Log of Mutations.

# Front End Nodes
Front end nodes submit mutations into the queue. 

In previous iterations, the nodes would also receive all mutations and apply 
them to their local copies of the tree. In this revision, we decided the tree
could be too big to fit on any particular node, so the tree has been moved to 
a distributed database that the Signer updates.

# Log of Mutations
Stores a signed list of mutations and epoch advancement markers that come out of 
the queue.

# Log of Signed Map Heads
Stores a signed list of Signed Map Heads (SMHs), one for each epoch.


