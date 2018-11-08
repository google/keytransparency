# Key Transparency Architecture

![Architecture](images/architecture.png)

# Clients
Clients make requests to Key Transparency servers over HTTPS / JSON or gRPC.  

# Key Transparency Server
The front end servers reveal the mappings between user identifiers (e.g. email
address) and their anonymized index in the Trillan Map with the Verifiable
Random Function. 

The front ends also provide account data for particular users and the mappings
between that account data and the public commitments stored in the Trillian
Map.

# Commitment Table
The commitment table stores account values and the associated commitment key 
nessesary to verify the commitment stored in the Trillian Map. 

# Mutation Table
When a user wishes to make a change to their account, they create a signed change
request (also known as a mutation) and send it to a Key Transparency frontend.

The frontend then saves the mutation in the mutation table, allowing the database 
to assign the mutation a monotonically increasing sequence number or timestamp, 
establishing an authoritative ordering for new mutations.

This strict ordering requirement could be relaxed in the future for
performance reasons.  Strictly speaking only given sets (batches) of mutations
that need to be ordered relative to other sets.

# Trillian Map
The Trillian Map stores the sparse merkle tree and is designed to scale to
extremely large trees. The Trillian Map is updated in batches.

# Trillian Log
The Trillian Log stores a dense merkle tree in the style of Ceritificate 
Transparency.  The Key Transparency Sequencer adds SignedMapRoots from the
Trillian Map to the Trillian Log as they are created. 

# Key Transparency Sequencer
The Key Transparency Sequencer runs periodically.  It creates a batch of new 
mutations that have occurred since the last sequencing run. It then verifies 
the mutations and applies them to the currently stored values in the map.

After each new map revision, the sequencer sends the new SignedMapRoot (SMR) to
the Trillian Log which must sequence the new SMR before the front ends will
start using the new map revision. 

After each new map revision, the sequencer will also send the new SignedMapRoot,
SignedLogRoot, Mutations, and associated proofs to the front ends over a
streaming gRPC channel. The frontends will then forward those same notification
to active monitors over a streaming gRPC channel.

# Mutation
Mutations in Key Transparency are defined as a signed key-value object. 
- The Key must be the valid index associated with the user's identifier.
- The Value is an object that contains 
   - A cryptographic commitment to the user's data.
   - The set of public keys that are allowed to update this account.
- The mutation also contains the hash of the previous mutation. This helps
  break race conditions and it forms a hash chain in each account.

# Monitors
Monitors process and verify the mutations that make each new revision.
Monitors verify various policy properties of the signed key-values in the
Trillian Map.  In particular, monitors verify that 
- Back pointers in each leaf do not skip over any values - an operation that
  would be bandwidth intensive for mobile clients.  
- Mutations are properly signed and verified by public keys declared in the
  prior revision. 

Monitors also observe the Trillian Log proofs provided by the Key Transparency 
front end to detect any log forks.  

Monitors participate in a primitive form of gossip by signing the Trillian Log
roots that they see and make them available over an API.




