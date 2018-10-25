# Key Transparency Contributions

## Efficiency and Speed

We needed Key Transparency to work on mobile devices which meant minimizing
network utilization. We were able to achieve a logarithmic performance increase
by switching from the hash chains used by CONIKS to Certificate Transparency
Logs and Monitors.

Using a more efficient data structure also allowed us to rapidly update the
system without imposing a high network bandwidth overhead for clients that
would previously need to download each update.  This improved system
responsiveness and user experience while also keeping the system simple and
robust.

## Redundancy

Experience has taught us that all systems need redundancy.  As we looked at
CONIKS, we realized we needed a way to achieve a separation of responsibilities
between the transparency properties of the system, and the certification
authority that the system represented.

We achieve this redundancy by using multiple append-only transparent logs to
hold snapshots of the Merkle tree data structure and the requests that built
the data structures. Monitors look for discrepancies between the logs.

## Scale and Storage

Our systems also needed to handle large volumes of data quickly. Typically this
means using advanced databases and sharding requests between many servers.
However, Key Transparency offers continually up-to-date cryptographic global
snapshots of the data which made this a non-trivial task for computation and
data storage. We ended pairing each section of the data structure with its own
dedicated compute for up-to-date cryptographic summaries of each section.

## Account Recovery

To provide a solution that can be deployed to users of all skill-sets without
the risk of account loss, a robust and flexible account recovery mechanism is
needed. Our goal is to enable users as well as authorized third-parties to
facilitate account recovery while retaining the transparency properties of the
log.

## References
*   [Why Making Jonny's Key Management Transparent Is So Challenging ](https://freedom-to-tinker.com/2016/03/31/why-making-johnnys-key-management-transparent-is-so-challenging/)
*   [Why Johnny Can't Encrypt: A Usability Evaluation of PGP 5.0](http://www.gaudior.net/alma/johnny.pdf)
*   [Why Johnny Still Can't Encrypt](https://pdfs.semanticscholar.org/c456/13ad59d4ad27a85322807a9a3e8532d978c5.pdf)
*   [Why Johnny Still, Still Can't Encrypt](https://arxiv.org/pdf/1510.08555v2.pdf)
*   [Safety number updates](https://whispersystems.org/blog/safety-number-updates/)
*   [I'm throwing in the towel on PGP, and I work in security](http://arstechnica.com/security/2016/12/op-ed-im-giving-up-on-pgp/)
*   [PGP Never Gonna Give You Up](https://cpbotha.net/2016/12/11/pgp-never-gonna-give-you-up/)
