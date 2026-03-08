# Missing: PSK Secret Computation (RFC 9420 Section 8.4)

## Status

The library currently takes `psk_secret` as a raw byte array input to the key schedule. There is no implementation of the PSK secret derivation algorithm that computes `psk_secret` from a list of pre-shared keys.

## What RFC 9420 Section 8.4 Requires

The PSK secret is derived by folding over a list of PSKs using an iterative Extract/ExpandWithLabel chain:

```
psk_secret_[0] = 0  (zeros of length KDF.Nh)

psk_secret_[i] = ExpandWithLabel(
    KDF.Extract(
        ExpandWithLabel(psk_secret_[i-1], "derived psk", PSKLabel_[i], KDF.Nh),
        psk_[i]
    ),
    "derived psk",
    PSKLabel_[i],
    KDF.Nh
)

psk_secret = psk_secret_[n]  (after processing all n PSKs)
```

Where `PSKLabel` is a TLS-serialized struct:

```
struct {
    PreSharedKeyID id;
    uint16 index;      // 0-based position in PSK list
    uint16 count;      // total number of PSKs
} PSKLabel;
```

And `PreSharedKeyID` contains the PSK type, ID bytes, and a nonce.

## What's Needed

1. **`ComputePskSecret` function** — Takes a list of `(psk_id, psk_value, psk_nonce)` tuples, serializes each `PSKLabel`, and performs the iterative derivation.

2. **PSK types** — RFC 9420 defines PSK types: `external` (0x01) and `resumption` (0x02). The function needs to handle both.

3. **Integration** — Wire this into `KeyScheduleEpoch.Create` and `FromJoinerSecret` so callers can pass PSK lists instead of a pre-computed `psk_secret`.

## Test Vectors Available

The `psk_secret.json` test vector file contains 11 test cases for cipher suite 1, ranging from 0 to 10 PSKs. Each provides:
- `psks[]` — list of `{psk_id, psk, psk_nonce}` for each PSK
- `psk_secret` — expected output

The 0-PSK case already works (output is all zeros). The 1+ PSK cases need the implementation above.

## Impact

Without this, the library cannot:
- Process Welcome messages that include external PSKs
- Re-initialize groups using resumption PSKs
- Support any multi-PSK scenarios

For basic group operations without PSKs (the common case), the current `psk_secret = zeros(Nh)` default is correct.
