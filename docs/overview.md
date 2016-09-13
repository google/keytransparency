# Key Transparency Overview

## Introduction

Today’s End-to-End encryption protocols encrypt messages using the public key
of the recipient before leaving the user’s device, making the messages
unreadable by the service provider and other 3rd parties.  However, these
products rely on the service provider to provide the public-key, or identity,
of the recipient, which makes these products vulnerable to man-in-the-middle
attacks facilitated by the service provider. In essence, the messages may be
encrypted, but who they’re encrypted to may be faked. The service provider can
simply route the encrypted messages to itself and read their contents.
Furthermore, this attack is undetectable because the service provider is under
no requirement to give consistent answers, and can return benign results when
it is being audited and malicious results when it is not. 

Key Transparency allows the service provider to be audited by enforcing
consistent results and requiring the provider to provide an accurate account
history. With these verifiable guarantees in-place, users will be able to rest
in the confidence that any attempt to redirect incoming messages by faking
their identity will be immediately detectable by the user. 

### Security Properties

#### Consistent results

Two users, querying for the public keys associated with the same account at the
same time will receive the same result. This allows receivers to verify their
account and have confidence that senders will be operating on the same
information. This shows that no third party has gained access to the
conversation by impersonating one of the parties.

To accomplish this, the full database of accounts and their public keys are
hashed together, using a Merkle Tree, and the resulting hash is shared
(gossiped) between users themselves. The tree hash is constructed to be
efficient and support proving that a piece of data is contained in the hash.
User apps use this hash to verify that the results are part of the same hash. 

![drawing](images/tree1.svg)

Root Merkle Tree Hash efficiently hashes whole database

![drawing](images/tree2.svg)

Merkle Tree Hash being used to prove that Leaf A is part of the root hash K by
hashing Leaf A, and then combining the resulting hash E with with intermediate
nodes F and J to compute K.  If the computed K is equal to the known-good K,
the proof is correct and Leaf A is part of K. 

If the computed K is not equal to the known-good K, stop and display a data
corruption warning.

To show that there is a single entry in the merkle tree for each user we number
the leaf nodes from 0 to 2^256-1, and designate a single leaf node for each
user by the pseudo-hash of their email address. See below for a discussion of
the privacy preserving properties of the specific hash function that is used. 

If the location provided does not match the pseudo-hash of the email address,
stop and display a wrong-user warning. 

![drawing](images/tree3.svg)

Merkle Tree with 256 levels to accommodate 2^256-1 leaf nodes 

#### Accurate Account History

When recipients audit their account they have confidence that senders will be
using the correct public keys for them if they were to send something *right
now*.  To give confidence that the user’s account remains secure through time,
Key Transparency provides an auditable account history. 

To detect spurious keys, users might label the keys that they recognize with
the device that the private keys are on.  Their client software could then
alert them to new / unknown devices. 

![drawing](images/uimock1.svg)
![drawing](images/uimock2.svg)


Example of how users might view their history to detect any unauthorized keys
in the past.

The red Unknown indicates an unlabeled key, which may be either malicious, or a
new device. 

To update accounts, the server collects all the changes requested every few
seconds, bundles them up, and creates a new snapshot of the database along with
a new merkle tree root. All previous snapshots and roots are available for
inspection at any time by the account holder. 

To ensure that previous snapshots are not misrepresented, the merkle tree roots
of each snapshot are stored in another merkle tree that is also gossiped. 

![drawing](images/tree4.svg)

Merkle Tree with the roots of each snapshot 

This is the same merkle tree structure as is used in Certificate Transparency

Because this merkle tree is filled in from left to right, there exists a proof
between any two states of the tree showing that each new state is an
append-only version of a previous state. 

![drawing](images/tree5.svg)

And append-only proof in bold, showing that the new state of the tree is equal
to the old tree plus snaps 4-6. 

#### Privacy

Public keys often contain personal information such as email addresses that
would be harmful to publish all at once for spam reasons. Rather than
publishing all the raw public keys, Key Transparency publishes cryptographic
commitments to the public keys and then reveals them when the public keys for
individual accounts are requested.  This is analogous to putting each key in a
sealed envelope, and then only opening the envelopes one at a time. 

The location of an account in the Merkle Tree may also leak a user’s email
address. To prevent this, Key Transparency uses a Verifiable Random Function
(VRF) to determine the location of a user in the tree, and provides
proof-of-correctness when an individual account is requested. 

Both techniques preserve the auditability of the whole data structure without
inordinately leaking the whole set of user identifiers. With knowledge of an
email address, individual accounts and their specific contents can be further
verified. 

## Further Information

*   [Design Doc](docs/design.md)
*   [Verification Algorithm](docs/verification.md)

