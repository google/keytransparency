# Meet In The Middle Algorithm

### Purpose
Enable a **sender** Bob at revision *fetched* and a **receiver** Alice at
revision *current* to perform append-only proofs between revisions *fetched* <=
*intermediate* <= *current*, without coordinating.

### Background
Key Transparency 1.0 allowed Bob to fetch at an unknown revision, requiring
Alice to fetch *all* revisions in order to verify her key history, an O(n)
amount of work where n is the number of revisonis between verifications. This
limited the frequency and freshness of directory updates.

The meet in the middle algorithm shares the work between Alice and Bob by
selecting O(Log(n)) potential intermediates, with the assurance that one of
them will be shared between Alice and Bob.  This brings the amount of
verification work down to a logarithmic, regardless of directory freshness. 

## Algorithm

### Sender Verificatoin
Clients save the (earliest) revision number associated with the data they have
fetched.  For Key Transparency, this means that *senders* will store, for each
contact, the contact's public key, map revision number it was fetched at, and
the latest revision it has been verified against.

Senders will then periodically verify that the map has not deleted evidence of
the public key they are relying on by querying the map at select revisions and
verifying that the contact's history of public keys is append-only.

The revisions to verify are as follows:

```
rev[i] = fetched - fetched mod 2ⁱ + 2ⁱ
```

### Receiver Verification

Receivers save, for their own keys, the latest revision they have verified.

Receivers periodically (Tuneable to their own security tolerance) verify that
the current version of their key history contains all keys previously contained
in the map at select previous versions.  

The revisions to verify are as follows:

```
rev[i] = current - current mod 2ⁱ
```
