# Key Transparency Use Cases


Key Transparency ensures, with mathematical certainty, that account owners can
see all the public keys that have been associated with their account.  

This zero-trust architecture is useful in a variety of scenarios from end-to-end encryption to enterprise account management.
Any scenario that involves authenticating users with public keys can significantly benefit from Key Transparency.

## Scenarios 

|  **Scenario** |  **Description** | 
|---------------|------------------|
| Encrypted Messaging | Key Transparency is ideal for user friendly end-to-end encrypted messaging.  By making key management analogous to device management, users do not have to learn any new concepts, and no additional UI beyond device management is needed. Key management fits seamlessly into existing account life-cycle flows, and users are protected without requiring them to take additional actions. |
| PGP Encrypted Email | Key Transparency was initially built to solve the problem of public key lookup for PGP email encryption. KT has the potential to make PGP significantly more usable than the existing web-of-trust model. |
| Insider Risk        | Key Transparency removes the possibility that a system administrator, whether accidentally, on purpose, or via a hack, might add or remove public keys (eg. [U2F Security Keys](https://en.wikipedia.org/wiki/Universal_2nd_Factor)) from a user account without detection. This enables new levels of security in authentication systems. |
| Post Compromise Security Audit | By relying on mathematics, Key Transparency significantly reduces the trusted computing base (TCB) of an authentication system.  This makes reasoning about the security properties of an enterprise under attack much easier.  The system administrator can have certainty that the authentication records for all accounts are intact, and that users will be able to quickly correct any account compromise. | 
| Cloud Adoption      | By employing a zero-trust architecture, Key Transparency provides *efficient evidence* to relying parties that the authentication system is operating correctly on an ongoing basis.  This can increase cloud product adoption by removing one system from the list of systems that are difficult for customers to audit and control. |

