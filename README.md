# FROST-Ed25519

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of a [FROST](https://eprint.iacr.org/2020/852.pdf) threshold signature protocol for the Ed25519 signature scheme.

Our FROST protocol implementation is also inspired from that in the IETF Draft [Threshold Modes in Elliptic Curves ](https://www.ietf.org/id/draft-hallambaker-threshold-05.html).

## Ed25519

Ed25519 is an instance of the EdDSA construction, defined over the Edwards 25519 elliptic curve.
FROST-Ed25519 is compatible with Ed25519, in the sense that public keys follow the same prescribed format,
and that the same verification algorithm can be used.

Specifically, we implement the _PureEdDSA_ variant, as detailed in [RFC 8032](https://tools.ietf.org/html/rfc8032)
(as opposed to HashEdDSA/Ed25519ph or ContextEdDSA/Ed25519ctx.).

### Ristretto

In order to minimize the impact of the cofactor in the Edwards 25519 elliptic curve, we represent the curve points with the
[Ristretto](https://ristretto.group/) encoding.
Our implementation is taken from Filippo Valsorda's [branch](https://github.com/gtank/ristretto255/tree/filippo/edwards25519backend)
of George Tankersley's [ristretto255](https://github.com/gtank/ristretto255).
Internally it uses the [edwards25519](https://github.com/FiloSottile/edwards25519) package.

We add a `BytesEd25519()` method on group elements which allows us to recover an Ed25519 compatible encoding of the curve point.
As elements are represented internally by `edwards25519.Point`, we take this point `P` and remove the cofactor by computing `P' = [8^{-1}][8]P`.
The result is the canonical encoding of `P'`.

For clarity, we distinguish the following elements:

- `B` is the base point of the Edwards 25519 elliptic curve
- `G` is the generator of the Ristretto group

The integer `q` is equal to `2**252 + 27742317777372353535851937790883648493` and is the prime order of the Ristretto group `<G>`.

### Keys

The Ed25519 standard defines the private signing key as a 32 byte _seed_ `x`.
Taking the SHA-512 hash of `x` yields two 32 byte strings by splitting the output in two equal halves: `SHA-512(x) = s || prefix`.
The value `s` encodes 32 byte integer, while the `prefix` is used later for deterministic signature generation.
The public key is the canonical representation of the elliptic curve point `A = [s mod q] • B`.

In FROST-Ed25519, a group of `n` parties `P1, ..., Pn` each hold a _Shamir share_ `s_i` of the secret integer `s`.
These shares are represented as integers mod `q`.
Given any set of at least `t+1` distinct shares, it is possible to recover the original full secret key `s mod q`. 
The integer `t` is the _threshold_ of the scheme, and defines the maximum number of parties that could act maliciously (i.e. collaborate to recover the key).

In FROST-Ed25519, the parties obtain their shares of `s` by executing the ChillDKG protocol (a Distributed Key Generation protocol adapted from the [BIP-FROST-DKG](https://github.com/BlockstreamResearch/bip-frost-dkg) specification).
In addition to receiving individual shares `s_i`, all parties also obtain the _group key_ `A = [s]•G`, and its associated public shares `{A_i = [s_i]•G}`.

After a successful execution of the DKG protocol, each party `Pi` obtains:

- a secret share `s_i` represented as a [`eddsa.SecretShare`](pkg/eddsa/secret_share.go) struct
- a set of all public shares `{A_i}` stored in [`eddsa.Public`](pkg/eddsa/public.go) struct
- the group key `A` represented as a [`eddsa.PublicKey`](pkg/eddsa/public_key.go), and stored in the `GroupKey` field of [`eddsa.Public`](pkg/eddsa/public.go).
  Calling `PublicKey.ToEd25519()` returns an `ed25519.PublicKey` compatible with the Ed25519 standard.
  
### Signatures

A FROST-Ed25519 signature for a message `M` is defined by a pair `(R,S)` where: 

- The nonce `R` represents a Ristretto group element, computed as `R = [r]•G` for some `r` mod `q`.
- `S` is a scalar derived computed as

```
R = [r]•G
k = SHA-512(R.BytesEd25519() || A.BytesEd25519() || M)
S = (r + k * s) mod q
```

In the original Ed25519 scheme, the nonce `R = [r]•B` is generated deterministically using the `prefix` in the key generation,
and the integer `r` is computed as `r = H( prefix || M )`.
For threshold signing, it is harder to generate nonce in such a deterministic way.
In FROST-Ed25519, the nonce pair `(r,R)` is generated as detailed in the [FROST paper](https://eprint.iacr.org/2020/852.pdf)

For compatibility with Ed25519, `k` is computed by encoding `R` and `A` as their canonical representations in the edwards25519 curve (cofactor-less).

Signatures are represented by the [`eddsa.Signature`](pkg/eddsa/signature.go) type.

### Verification

The verification algorithm takes a public key `A`, the signed message `M`, and its signature `(R,S)`.
It does the following:

- Recompute `k = SHA-512(R.BytesEd25519() || A.BytesEd25519() || M) mod q` 
- Verify the equality `R == [-k]•A + [S]•G`

Manual verification is not necessary in most cases, but is possible by calling `PublicKey.Verify(message []byte, signature *eddsa.Signature)`.

_Note_: the cofactor is no longer an issue here, since we are considering points in the Ristretto group.

### Compatibility with `ed25519`:

The goal of FROST-Ed25519 is to be compatible with the `ed25519` library included in Go.
In particular, the [`frost.PublicKey`](pkg/eddsa/public_key.go) and [`frost.Signature`](pkg/eddsa/signature.go) types can be converted to the `ed25119.PublicKey` and `[]byte` types respectively,
by calling `.ToEd25519()`.

### Example

The following example shows some possible interaction with the types described above:

```go
var (
    id          party.ID                // id of the party
    secretShare *eddsa.SecretShare      // private output of DKG for party id
    public      *eddsa.Public           // public output of DKG
    message     []byte                  // message signed
    groupSig    *eddsa.Signature        // signature produced by sign protocol for message
)

groupKey := public.GroupKey
// use the ed25519 library
ed25519.Verify(groupKey.ToEd25519(), message, groupSig.ToEd25519()) // = true

secretShare.ID == id    // = true
```

## FROST Protocol — Mathematical Description

This section describes the mathematical foundations of FROST as implemented in this project. The implementation follows the FROST1/FROST2 variant with per-party binding factors.

### Key Generation (ChillDKG)

Key generation uses **ChillDKG**, a fully standalone DKG protocol adapted from the [BIP-FROST-DKG](https://github.com/BlockstreamResearch/bip-frost-dkg) specification. ChillDKG replaces the basic Pedersen DKG used in the original FROST paper with a three-layered protocol that provides encrypted share transport, built-in agreement, recovery, and blame identification — all without requiring external secure channels or consensus mechanisms.

#### Why ChillDKG instead of Pedersen DKG

The original FROST paper specifies a Pedersen-style DKG where shares are sent in plaintext over assumed secure channels, participants have no way to agree on whether the DKG succeeded, faulty participants cannot be identified, and lost shares are unrecoverable. ChillDKG solves all of these problems:

| Property | Pedersen DKG | ChillDKG |
|---|---|---|
| Share transport | Plaintext (requires secure channels) | ECDH-encrypted |
| Agreement | None (requires external consensus) | Built-in (CertEq protocol) |
| Blame | None | Identifies faulty participants |
| Recovery | None | From host key + recovery data |
| Topology | Peer-to-peer | Coordinator-relay |

#### Architecture

ChillDKG is internally composed of three layers, each adding functionality:

| Layer | Protocol | What it adds |
|-------|----------|-------------|
| 1 | **SimplPedPop** | Simplified Pedersen DKG with proofs of possession |
| 2 | **EncPedPop** | Wraps SimplPedPop with ECDH encryption of shares |
| 3 | **ChillDKG** | Wraps EncPedPop with CertEq equality check |

These layers execute together as a single protocol. The full ChillDKG protocol runs in 3 rounds for participants and 2 rounds for the coordinator:

```
Setup:
  Each participant has a long-term host keypair (hostseckey, hostpubkey).
  All parties agree on SessionParams = (hostpubkeys[], t).

Round 1 (participant → coordinator):
  Generate VSS polynomial, proof of possession, ECDH nonce.
  Encrypt partial secret shares to each participant using ECDH.

Coordinator aggregation:
  Aggregate commitments and encrypted shares.

Round 2 (participant → coordinator):
  Verify proofs of possession, decrypt aggregated share via ECDH,
  verify share against VSS commitment, sign transcript with CertEq.

Coordinator finalization:
  Collect all CertEq signatures into certificate.

Round 3 (participant finalization):
  Verify certificate, output final DKG result + recovery data.
```

#### Mathematical Details

Each party `P_i`:

1. Generates a deterministic VSS polynomial `f_i(x)` of degree `t` from a seed derived via tagged hashing.
2. Computes commitments `C_{i,j} = [a_{i,j}] • G` for `j = 0, ..., t`.
3. Produces a Schnorr proof of possession (signature on its index with the VSS secret key).
4. Encrypts partial shares `f_i(j)` to each party `P_j` using Hashed ElGamal multi-recipient KEM over ECDH.

The coordinator aggregates commitments and encrypted shares (homomorphic sum of ciphertexts). Each participant decrypts their aggregated share and verifies it against the aggregated VSS commitment.

After successful verification:

- Party `P_i`'s secret share: `s_i = Σ_j f_j(i) mod q`
- The group secret (never reconstructed): `s = Σ_j a_{j,0} mod q`
- The group public key: `A = [s] • G = Σ_j C_{j,0}`
- Party `P_i`'s public share: `A_i = [s_i] • G`

The CertEq protocol ensures all honest participants agree on the DKG output by having each participant sign a transcript hash with their host key, and verifying all signatures before accepting.

**Implementation**: [`pkg/frost/chilldkg/`](pkg/frost/chilldkg/)

### Signing Protocol

Signing is a 2-round protocol executed by a subset `T` of `t+1` parties. It produces a standard Schnorr signature `(R, S)` verifiable with the group key `A`.

#### Round 0 — Preprocessing (PreRound)

Each signer `P_i` samples fresh nonce pairs:

```
d_i ←$ Z_q,    D_i = [d_i] • G
e_i ←$ Z_q,    E_i = [e_i] • G
```

and broadcasts `(D_i, E_i)` to all other signers.

**Implementation**: [`pkg/frost/sign/round0.go`](pkg/frost/sign/round0.go)

#### Round 1 — Signing (SignRound)

After receiving all `(D_j, E_j)` from other signers in `T`, each signer computes:

1. **Binding factors** (per-party, to prevent forgery attacks):
   ```
   B = (ID_1 ∥ D_1 ∥ E_1) ∥ ... ∥ (ID_n ∥ D_n ∥ E_n)
   ρ_j = SHA-512("FROST-SHA512" ∥ j ∥ SHA-512(M) ∥ B)    for each j ∈ T
   ```

2. **Per-party nonce commitments**:
   ```
   R_j = D_j + [ρ_j] • E_j    for each j ∈ T
   ```

3. **Aggregate nonce**:
   ```
   R = Σ_{j ∈ T} R_j
   ```

4. **Challenge** (standard Schnorr):
   ```
   c = SHA-512(R.BytesEd25519() ∥ A.BytesEd25519() ∥ M) mod q
   ```

5. **Signature share**:
   ```
   σ_i = d_i + ρ_i • e_i + c • Λ_{T,i} • s_i   mod q
   ```

Each signer broadcasts `σ_i`.

**Implementation**: [`pkg/frost/sign/round1.go`](pkg/frost/sign/round1.go)

#### Round 2 — Aggregation and Verification

Each party verifies every other signer's share using the public information:

```
[σ_j] • G  ==  R_j + [c • Λ_{T,j}] • A_j
```

which is equivalent to checking (using the efficient double-scalar multiplication):

```
[c] • (-[Λ_j] • A_j) + [σ_j] • G  ==  R_j
```

If all shares verify, the final signature is:

```
S = Σ_{j ∈ T} σ_j   mod q
σ = (R, S)
```

**Correctness proof**: The signature `(R, S)` is a valid Schnorr signature because:

```
[S] • G = Σ_j [σ_j] • G
        = Σ_j (R_j + [c • Λ_j] • A_j)
        = R + [c] • Σ_j [Λ_j] • A_j
        = R + [c] • A
```

which is exactly the Schnorr verification equation `[S] • G = R + [c] • A`.

**Implementation**: [`pkg/frost/sign/round2.go`](pkg/frost/sign/round2.go)

### Share Validation (Identifiable Aborts)

If a signer `P_j` submits an invalid signature share `σ_j`, the other parties can identify the cheater by checking:

```
[σ_j] • G  ≠  R_j + [c • Λ_{T,j}] • A_j
```

This property (IA-CMA) is critical for the ROAST wrapper, which uses it to exclude malicious signers and retry with honest ones.

### Security Properties

| Property | Guarantee |
|---|---|
| **Unforgeability** | No coalition of up to `t` malicious signers can forge a signature (under OMDL in ROM) |
| **Identifiable aborts** | If a session fails, at least one malicious signer is identified |
| **Concurrent security** | Multiple signing sessions can run safely in parallel |
| **Compatibility** | Output signatures are standard Ed25519 Schnorr signatures |

### ROAST — Robust Asynchronous Wrapper

ROAST is a wrapper protocol that turns FROST into a robust and asynchronous signing protocol. It is implemented in [`pkg/roast/`](pkg/roast/).

A semi-trusted coordinator maintains a set `R` of responsive signers. Whenever `|R| ≥ t+1`, the coordinator initiates a new FROST signing session with those signers. Each signer responds with a signature share `σ_i` for the current session and a fresh presignature share `(D'_i, E'_i)` for the next session (pipelining).

If a signer provides an invalid share, it is marked malicious via `ShareVal` and excluded. If a signer is non-responsive, its session may fail, but the coordinator initiates a new session with the remaining responsive signers.

**Key invariant**: Each signer is pending in at most one session at a time. With `f ≤ n - t - 1` malicious signers, at most `f + 1` sessions are needed, and the protocol terminates after at most `n - t + 1` sessions (Theorem 4.3 from the ROAST paper).

**Usage via CLI**:
```bash
go run ./cmd/keygen/ 2 5          # generate keys: t=2, n=5
go run ./cmd/roast/ keygenout.json "message"      # sign with ROAST
go run ./cmd/roast/ keygenout.json "message" 2    # sign with 2 simulated malicious signers
```

### Protocol Variant

The FROST paper proposes two variants of the protocol. 
We implement the "single-round" version of FROST, rather than the 4-round variant FROST-Interactive.

The single-round version does one "offline" round, followed by one "online" round, where the offline round does not need the message and can therefore be precomputed.
For simplicity, we group both steps together and achieve a 2 round protocol that requires less state handling.
We also ignore the role of _signature aggregator_ and instead let the parties broadcast the signature shares to each other to obtain the full signature.

This variant is the one that is proposed for practical implementations, however it does not have a full security proof, unlike FROST-Interactive (see [Section 6.2](https://eprint.iacr.org/2020/852.pdf) of the FROST paper).

## Instructions

This FROST-Ed25519 implementation includes a round-based architecture for key generation and signing.
Key generation uses ChillDKG ([`pkg/frost/chilldkg/`](pkg/frost/chilldkg/)), and signing uses FROST ([`pkg/frost/sign/`](pkg/frost/sign/)).
The signing protocol is handled by a [`State`](pkg/state/state.go) object that takes care of storing messages, passing them to the round at the right time, and reporting any error that may have occurred.

Users of this library should only interact with [`State`](pkg/state/state.go) types. 

### Basics

Each party must be assigned a unique numerical [`party.ID`](pkg/frost/party/id.go) (internally represented as an `uint16`).
A set of `party.ID`s is stored as a [`party.IDSlice`](pkg/frost/party/set.go) which wraps a slice and ensures sorting.

Optionally, a `timeout` argument can be provided, to force the protocol to abort if the time duration between two received messages is longer than `timeout`.
If it is set to 0, then there is no limit.

For signing, a [`State`](pkg/state/state.go) can be created by calling [`frost.NewSignState`](pkg/frost/frost.go), which returns:
- A [`State`](pkg/state/state.go) object used to interact with the protocol
- An `Output` object whose attributes are initialized to `nil`, and populated asynchronously when protocol has successfully completed.
- An `error` indicating whether the state was successfully created.

An example of how to use the library can be found in [example/main.go]().

### Keygen

Key generation uses ChillDKG, a coordinator-relay protocol. Each participant needs a long-term host keypair and agreed-upon session parameters.

```go
import (
    "github.com/taurusgroup/frost-ed25519/pkg/frost/chilldkg"
    "github.com/taurusgroup/frost-ed25519/pkg/frost/party"
    "github.com/taurusgroup/frost-ed25519/pkg/ristretto"
)

hostseckeys := make([]*ristretto.Scalar, n)
hostpubkeys := make([]ristretto.Element, n)
for i := 0; i < n; i++ {
    sk, pk, _ := chilldkg.GenerateHostKey()
    hostseckeys[i] = sk
    hostpubkeys[i] = *pk
}

params := &chilldkg.SessionParams{
    HostPubkeys: hostpubkeys,
    Threshold:   party.Size(t),
}

outputs, recoveryData, err := chilldkg.SimulateSession(hostseckeys, params)
```

`SimulateSession` runs the full 3-round ChillDKG protocol in-memory. For networked deployments, use `ParticipantStep1`, `CoordinatorStep1`, `ParticipantStep2`, `CoordinatorFinalize`, and `ParticipantFinalize` individually.

To convert ChillDKG output to FROST signing types:

```go
public, secretShares, err := chilldkg.OutputToFROST(outputs, params)
```

The output contains:
- [`Public`](pkg/eddsa/public.go): public key shares of all parties and the group key.
- [`SecretShare`](pkg/eddsa/secret_share.go): each party's share of the group signing key.
- `RecoveryData`: allows restoring DKG output from a host key if shares are lost.

### Sign


```go
var (
        partyIDs    party.IDSlice       // slice of party IDs which will be performing the signing (must be of length at least `threshold`+1)
        secret      *eddsa.SecretShare  // the secret key share obtained from the keygen protocol
        public      *eddsa.Public       // contains the public information including the group key and individual public shares
        message     []byte              // message in bytes to be signed (does not need to be prehashed)
        timeout     time.Duration       // maximum time allowed between two messages received. A duration of 0 indicates no timeout
)

state, output, err := frost.NewSignState(partySet, secret, public, message, timeout)
```

Once the protocol has finished, the [`output`](pkg/frost/sign/output.go) contains a single field for the [`Signature`](pkg/eddsa/signature.go):

The Signature can be verified using Go's included `ed25519` library, by converting the group key and signature to compatible types.
```go
ed25519.Verify(shares.GroupKey.ToEd25519(), message, output.Signature.ToEd25519())
```

or alternatively,


### Transport Layer

If the round was successfully executed, `State.ProcessAll()` returns a slice [`[]*messages.Message`](pkg/messages/messages.go).
It is up to the user of this library to properly route messages between participants.
The ID's of the sender and destination party of a particular [`messages.Message`](pkg/messages/messages.go) can be found in the `From` and `To` field of the embedded [`messages.Header`](pkg/messages/header.go)
on the [`messages.Message`](pkg/messages/messages.go) object.
Users should first check if the message is intended for broadcast by calling `.IsBroadcast()`, since the `To` field is undefined in this case.

```go
var msg messages.Message
data, err := msg.MarshalBinary()
if err != nil {
	// handle marshalling error, but we cannot continue
	return
}
if msg.IsBroadcast() {
	// send data to all parties except ourselves
} else {
	dest := msg.To
	// send data to party with ID dest
}
```

On the reception, the message should be unmarshalled and then given to the `State`:
```go
var data []byte
var msg messages.Message
err := msg.Unmarshal(data)
if err != nil {
	// handle marshalling error, but we cannot continue
	return
}
err = state.HandleMessage(&msg)
if err != nil {
	// May indicate that an error occurred during transport
	// does not mean we should abort necessarily
	return
}
```

### Testing

We include unit tests for individual modules, as well as a bigger integration tests in [test/](test/).
Full test coverage is however not guaranteed.

### Example usage

A simple example of how to use this library can be found in [test/sign_test.go](test/sign_test.go), [test/keygen_test.go](test/keygen_test.go), and [example/main.go](example/main.go).

## Security

This library was NOT designed to be free of side channels (timing, memory, oracles, and so on), and due to Go's intrinsic limitations most likely is not.

This library has yet to be audited and fully vetted for production usage.
Use at your own risk.

Please report any critical security issue to security@taurusgroup.ch.
We encourage you to use our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX3G3ARYJKwYBBAHaRw8BAQdA7sQCSqSkAmGylsLRJepXuAZKkcWA+EWRPeGa
22cIXYC0KVRhdXJ1cyBTZWN1cml0eSA8c2VjdXJpdHlAdGF1cnVzZ3JvdXAuY2g+
iJAEExYIADgWIQQ0q1qzH0uLrdBgWQWfaUpuIE2KEAUCX3G3AQIbIwULCQgHAgYV
CgkICwIEFgIDAQIeAQIXgAAKCRCfaUpuIE2KEFn9AP9uAyItJevrH8rV3K4zO25X
7nOI8MQJagBMnGxP+FdF7QD8D3LndQy2AefifK44v8BOKHs0J/hXtkIJTFLu6IzG
MwA=
=QNKX
-----END PGP PUBLIC KEY BLOCK-----
```

Issues that are not critical (not exploitable, DoS, and so on) can be reported as [GitHub Issues](https://github.com/taurusgroup/frost-ed25519/issues).


## Dependencies 

Our package has a [minimal set](./go.mod) of third-party dependencies, mainly Valsorda's [edwards25519](https://filippo.io/edwards25519).
We also include the single `ristretto255` file from [PR 41](https://github.com/gtank/ristretto255/pull/41)

## Intellectual property

This code is copyright (c) Taurus SA, 2021, and under Apache 2.0 license.

