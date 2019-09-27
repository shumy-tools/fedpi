# Federation of Pseudonymised Identities (Experimental)
The Fed![](https://latex.codecogs.com/gif.latex?%5CPi) project defines a complete architecture and theoretical formulation based on strong cryptographic foundations (Shamir Secret Sharing and Elliptic Curves). The main motivation is to present a GDPR compliant solution for Self-Sovereign Identities (SS-IDs), integrated with isolated and anonymous records (profiles), serving a multitude of data access requirements. I.e., for primary and secondary usages and implicit (break-the-glass) vs explicit (data-subject approved) consent. Secondary uses of data are useful to feed machine learning algorithms. Implicit consent is useful for break-the-glass requirements in healthcare records.

The target features for the project are:

- [ ] Managment of cryptographic keys. Backup, restore, revoke, etc.
- [ ] Implementing protocols for authorization, authentication, profile disclosure, data transmission, etc.
- [ ] Selective disclosure of anonymous profiles for "Data Minimisation".
- [ ] Providing implicit and explicit GDPR consent routes to disclose records.
- [ ] Providing methods to securely derive a pseudonym from a piece of public information, i.e. QR-Code, RFID, etc.
- [ ] Supporting non-repudiation of anonymous records. The ability to prove the existence and ownership of records, without the possibility of hiding unwanthed records (such as trying to hide a financial debt).
- [ ] Independent distributed data containers (Profile Servers) for anonymous records and profiles.
- [ ] Resilience to a variety of cyber security attacks, such as insider attacks, ransomware, viruses, worms, denial of service, etc.

To acomplish this objective the project defines the following core components:

### Identity Clients (i-client)
Client software under the direct control of the GDPR **data-subject** with the responsibility of protecting and managing the private data of a Self-Sovereign Identity.

### Terminals Clients (t-client)
Terminals are points of data management with read/write access. These are GDPR **processors** that require consent (implicit or explicit) to work with personal data. The main idea is to provide APIs for local applications, to help with the FedPI interaction.

### FedPI Nodes (f-node)
These nodes are used to deploy a distributed federation of SS-IDs. This is a GDPR **controller** with the responsability of protecting the SS-IDs (published data) and connections to anonymous data profiles. The FedPI network provides non-repudiation and methodologies to locate and disclose the anonymous profiles. Good security standards are extremely important for the design of the "f-node" software.

### Profile Servers (p-server)
Is where the anonymous or encrypted data resides, providing public of private access control. Any organization can deploy their own "p-server" for specific purposes and pre-defined data structures. The organization is the GDPR **controller** of the anonymous profiles, but doesn't retain data ownership.

## Semi-Completed Protocols
- [x] Subject creation and syncronization protocol
- [x] Master key negotiation protocol
