# SM OID Migration from Tongsuo to BoringSSL

## Summary

Migrate all SM (Chinese national cryptographic standard) OID definitions from Tongsuo project to BoringSSL, enabling full TLCP (GB/T 38636-2020) support.

## Background

Tongsuo (Alibaba's OpenSSL fork) contains comprehensive OID definitions for Chinese cryptographic algorithms (SM2, SM3, SM4, ZUC, etc.) under the OID root `1.2.156.10197.1` (sm-scheme). BoringSSL currently only has a minimal SM2 curve definition. To support TLCP protocol, we need the complete OID set.

## Design Decisions

1. **Scope**: Migrate all SM-related OIDs (~46 entries) from Tongsuo
2. **NID Assignment**: Auto-assign new NID values (not compatible with Tongsuo)
3. **Definition Style**: Hierarchical (define parent nodes, then reference them)
4. **Cross-Reference**: Manually add to `obj_xref.cc` (follow BoringSSL pattern)

## OID Definitions to Add

### Phase 1 - OID Root Hierarchy

```
member-body 156         : ISO-CN        : ISO CN Member Body
ISO-CN 10197            : oscca
oscca 1                 : sm-scheme
```

Establishes OID root `1.2.156.10197.1` (sm-scheme).

### Phase 2 - Core Algorithms

```
sm-scheme 301           : SM2           : sm2
sm-scheme 401           : SM3           : sm3
sm-scheme 501           : SM2-SM3       : SM2-with-SM3
sm-scheme 104 1         : SM4-ECB       : sm4-ecb
sm-scheme 104 2         : SM4-CBC       : sm4-cbc
sm-scheme 104 3         : SM4-OFB       : sm4-ofb
sm-scheme 104 4         : SM4-CFB       : sm4-cfb
sm-scheme 104 7         : SM4-CTR       : sm4-ctr
sm-scheme 104 8         : SM4-GCM       : sm4-gcm
sm-scheme 104 9         : SM4-CCM       : sm4-ccm
```

### Phase 3 - Extended Algorithms

```
sm-scheme 504           : RSA-SM3       : sm3WithRSAEncryption
sm3 3 1                 :               : hmacWithSM3
sm-scheme 201           : ZUC           : zuc
sm-scheme 801           : ZUC-128-EEA3  : zuc-128-eea3
sm-scheme 802           : ZUC-128-EIA3  : zuc-128-eia3
```

### Phase 4 - TLS Key Exchange/Auth

```
                        : KxSM2         : kx-sm2
                        : KxSM2DHE      : kx-sm2dhe
                        : AuthSM2       : auth-sm2
```

## Files to Modify

### Source Files

| File | Change |
|------|--------|
| `crypto/obj/objects.txt` | Add SM OID definitions (hierarchical style) |
| `crypto/obj/obj_xref.cc` | Add `{NID_SM2_with_SM3, NID_sm3, NID_sm2}` to kTriples |

### Generated Files (auto-updated)

| File | Content |
|------|---------|
| `crypto/obj/obj_mac.num` | NID number assignments |
| `include/openssl/nid.h` | NID macros |
| `crypto/obj/obj_dat.h` | DER-encoded OID data |

### Note on Existing SM2

The current inline definition will be removed:
```
member-body 156 10197 1 301	: SM2 : sm2
```
Replaced by hierarchical definition via `sm-scheme 301`.

## Implementation Steps

1. Modify `crypto/obj/objects.txt` - add all OID definitions
2. Run `cd crypto/obj && go run objects.go` to regenerate headers
3. Update `crypto/obj/obj_xref.cc` - add SM2-with-SM3 cross-reference
4. Build: `cmake -GNinja -B build && ninja -C build`
5. Test: `./build/crypto_test --gtest_filter=ObjTest*`

## Testing

- Verify `OBJ_txt2nid("SM2-with-SM3")` returns valid NID
- Verify `OBJ_find_sigid_algs(NID_SM2_with_SM3, ...)` returns correct digest/pkey mappings
- Verify SM4 cipher OIDs resolve correctly
- Verify ZUC algorithm OIDs resolve correctly
