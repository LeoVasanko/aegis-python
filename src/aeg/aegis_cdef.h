/* This file is generated with tools/generate.py. Do not edit. */

/* aegis.h */
int aegis_init(void);
int aegis_verify_16(const uint8_t *x, const uint8_t *y);
int aegis_verify_32(const uint8_t *x, const uint8_t *y);

/* aegis128l.h */
typedef struct aegis128l_state { uint8_t opaque[256]; } aegis128l_state;
typedef struct aegis128l_mac_state { uint8_t opaque[384]; } aegis128l_mac_state;
size_t aegis128l_keybytes(void);
size_t aegis128l_npubbytes(void);
size_t aegis128l_abytes_min(void);
size_t aegis128l_abytes_max(void);
size_t aegis128l_tailbytes_max(void);
int aegis128l_encrypt_detached(uint8_t *c,
                               uint8_t *mac,
                               size_t maclen,
                               const uint8_t *m,
                               size_t mlen,
                               const uint8_t *ad,
                               size_t adlen,
                               const uint8_t *npub,
                               const uint8_t *k);
int aegis128l_decrypt_detached(uint8_t *m,
                               const uint8_t *c,
                               size_t clen,
                               const uint8_t *mac,
                               size_t maclen,
                               const uint8_t *ad,
                               size_t adlen,
                               const uint8_t *npub,
                               const uint8_t *k);
int aegis128l_encrypt(uint8_t *c,
                      size_t maclen,
                      const uint8_t *m,
                      size_t mlen,
                      const uint8_t *ad,
                      size_t adlen,
                      const uint8_t *npub,
                      const uint8_t *k);
int aegis128l_decrypt(uint8_t *m,
                      const uint8_t *c,
                      size_t clen,
                      size_t maclen,
                      const uint8_t *ad,
                      size_t adlen,
                      const uint8_t *npub,
                      const uint8_t *k);
void aegis128l_state_init(aegis128l_state *st_,
                          const uint8_t *ad,
                          size_t adlen,
                          const uint8_t *npub,
                          const uint8_t *k);
int aegis128l_state_encrypt_update(aegis128l_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
int aegis128l_state_encrypt_final(aegis128l_state *st_, uint8_t *mac, size_t maclen);
int aegis128l_state_decrypt_update(aegis128l_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
int aegis128l_state_decrypt_final(aegis128l_state *st_, const uint8_t *mac, size_t maclen);
void aegis128l_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
void aegis128l_stream_xor(uint8_t *out,
                          const uint8_t *in,
                          size_t len,
                          const uint8_t *npub,
                          const uint8_t *k);
void aegis128l_encrypt_unauthenticated(uint8_t *c,
                                       const uint8_t *m,
                                       size_t mlen,
                                       const uint8_t *npub,
                                       const uint8_t *k);
void aegis128l_decrypt_unauthenticated(uint8_t *m,
                                       const uint8_t *c,
                                       size_t clen,
                                       const uint8_t *npub,
                                       const uint8_t *k);
void aegis128l_mac_init(aegis128l_mac_state *st_, const uint8_t *k, const uint8_t *npub);
int aegis128l_mac_update(aegis128l_mac_state *st_, const uint8_t *m, size_t mlen);
int aegis128l_mac_final(aegis128l_mac_state *st_, uint8_t *mac, size_t maclen);
int aegis128l_mac_verify(aegis128l_mac_state *st_, const uint8_t *mac, size_t maclen);
void aegis128l_mac_reset(aegis128l_mac_state *st_);
void aegis128l_mac_state_clone(aegis128l_mac_state *dst, const aegis128l_mac_state *src);

/* aegis128x2.h */
typedef struct aegis128x2_state { uint8_t opaque[448]; } aegis128x2_state;
typedef struct aegis128x2_mac_state { uint8_t opaque[704]; } aegis128x2_mac_state;
size_t aegis128x2_keybytes(void);
size_t aegis128x2_npubbytes(void);
size_t aegis128x2_abytes_min(void);
size_t aegis128x2_abytes_max(void);
size_t aegis128x2_tailbytes_max(void);
int aegis128x2_encrypt_detached(uint8_t *c,
                                uint8_t *mac,
                                size_t maclen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis128x2_decrypt_detached(uint8_t *m,
                                const uint8_t *c,
                                size_t clen,
                                const uint8_t *mac,
                                size_t maclen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis128x2_encrypt(uint8_t *c,
                       size_t maclen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
int aegis128x2_decrypt(uint8_t *m,
                       const uint8_t *c,
                       size_t clen,
                       size_t maclen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
void aegis128x2_state_init(aegis128x2_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis128x2_state_encrypt_update(aegis128x2_state *st_,
                                    uint8_t *c,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis128x2_state_encrypt_final(aegis128x2_state *st_, uint8_t *mac, size_t maclen);
int aegis128x2_state_decrypt_update(aegis128x2_state *st_,
                                    uint8_t *m,
                                    const uint8_t *c,
                                    size_t clen);
int aegis128x2_state_decrypt_final(aegis128x2_state *st_, const uint8_t *mac, size_t maclen);
void aegis128x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
void aegis128x2_stream_xor(uint8_t *out,
                           const uint8_t *in,
                           size_t len,
                           const uint8_t *npub,
                           const uint8_t *k);
void aegis128x2_encrypt_unauthenticated(uint8_t *c,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis128x2_decrypt_unauthenticated(uint8_t *m,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis128x2_mac_init(aegis128x2_mac_state *st_, const uint8_t *k, const uint8_t *npub);
int aegis128x2_mac_update(aegis128x2_mac_state *st_, const uint8_t *m, size_t mlen);
int aegis128x2_mac_final(aegis128x2_mac_state *st_, uint8_t *mac, size_t maclen);
int aegis128x2_mac_verify(aegis128x2_mac_state *st_, const uint8_t *mac, size_t maclen);
void aegis128x2_mac_reset(aegis128x2_mac_state *st_);
void aegis128x2_mac_state_clone(aegis128x2_mac_state *dst, const aegis128x2_mac_state *src);

/* aegis128x4.h */
typedef struct aegis128x4_state { uint8_t opaque[832]; } aegis128x4_state;
typedef struct aegis128x4_mac_state { uint8_t opaque[1344]; } aegis128x4_mac_state;
size_t aegis128x4_keybytes(void);
size_t aegis128x4_npubbytes(void);
size_t aegis128x4_abytes_min(void);
size_t aegis128x4_abytes_max(void);
size_t aegis128x4_tailbytes_max(void);
int aegis128x4_encrypt_detached(uint8_t *c,
                                uint8_t *mac,
                                size_t maclen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis128x4_decrypt_detached(uint8_t *m,
                                const uint8_t *c,
                                size_t clen,
                                const uint8_t *mac,
                                size_t maclen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis128x4_encrypt(uint8_t *c,
                       size_t maclen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
int aegis128x4_decrypt(uint8_t *m,
                       const uint8_t *c,
                       size_t clen,
                       size_t maclen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
void aegis128x4_state_init(aegis128x4_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis128x4_state_encrypt_update(aegis128x4_state *st_,
                                    uint8_t *c,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis128x4_state_encrypt_final(aegis128x4_state *st_, uint8_t *mac, size_t maclen);
int aegis128x4_state_decrypt_update(aegis128x4_state *st_,
                                    uint8_t *m,
                                    const uint8_t *c,
                                    size_t clen);
int aegis128x4_state_decrypt_final(aegis128x4_state *st_, const uint8_t *mac, size_t maclen);
void aegis128x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
void aegis128x4_stream_xor(uint8_t *out,
                           const uint8_t *in,
                           size_t len,
                           const uint8_t *npub,
                           const uint8_t *k);
void aegis128x4_encrypt_unauthenticated(uint8_t *c,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis128x4_decrypt_unauthenticated(uint8_t *m,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis128x4_mac_init(aegis128x4_mac_state *st_, const uint8_t *k, const uint8_t *npub);
int aegis128x4_mac_update(aegis128x4_mac_state *st_, const uint8_t *m, size_t mlen);
int aegis128x4_mac_final(aegis128x4_mac_state *st_, uint8_t *mac, size_t maclen);
int aegis128x4_mac_verify(aegis128x4_mac_state *st_, const uint8_t *mac, size_t maclen);
void aegis128x4_mac_reset(aegis128x4_mac_state *st_);
void aegis128x4_mac_state_clone(aegis128x4_mac_state *dst, const aegis128x4_mac_state *src);

/* aegis256.h */
typedef struct aegis256_state { uint8_t opaque[192]; } aegis256_state;
typedef struct aegis256_mac_state { uint8_t opaque[288]; } aegis256_mac_state;
size_t aegis256_keybytes(void);
size_t aegis256_npubbytes(void);
size_t aegis256_abytes_min(void);
size_t aegis256_abytes_max(void);
size_t aegis256_tailbytes_max(void);
int aegis256_encrypt_detached(uint8_t *c,
                              uint8_t *mac,
                              size_t maclen,
                              const uint8_t *m,
                              size_t mlen,
                              const uint8_t *ad,
                              size_t adlen,
                              const uint8_t *npub,
                              const uint8_t *k);
int aegis256_decrypt_detached(uint8_t *m,
                              const uint8_t *c,
                              size_t clen,
                              const uint8_t *mac,
                              size_t maclen,
                              const uint8_t *ad,
                              size_t adlen,
                              const uint8_t *npub,
                              const uint8_t *k);
int aegis256_encrypt(uint8_t *c,
                     size_t maclen,
                     const uint8_t *m,
                     size_t mlen,
                     const uint8_t *ad,
                     size_t adlen,
                     const uint8_t *npub,
                     const uint8_t *k);
int aegis256_decrypt(uint8_t *m,
                     const uint8_t *c,
                     size_t clen,
                     size_t maclen,
                     const uint8_t *ad,
                     size_t adlen,
                     const uint8_t *npub,
                     const uint8_t *k);
void aegis256_state_init(aegis256_state *st_,
                         const uint8_t *ad,
                         size_t adlen,
                         const uint8_t *npub,
                         const uint8_t *k);
int aegis256_state_encrypt_update(aegis256_state *st_, uint8_t *c, const uint8_t *m, size_t mlen);
int aegis256_state_encrypt_final(aegis256_state *st_, uint8_t *mac, size_t maclen);
int aegis256_state_decrypt_update(aegis256_state *st_, uint8_t *m, const uint8_t *c, size_t clen);
int aegis256_state_decrypt_final(aegis256_state *st_, const uint8_t *mac, size_t maclen);
void aegis256_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
void aegis256_stream_xor(uint8_t *out,
                         const uint8_t *in,
                         size_t len,
                         const uint8_t *npub,
                         const uint8_t *k);
void aegis256_encrypt_unauthenticated(uint8_t *c,
                                      const uint8_t *m,
                                      size_t mlen,
                                      const uint8_t *npub,
                                      const uint8_t *k);
void aegis256_decrypt_unauthenticated(uint8_t *m,
                                      const uint8_t *c,
                                      size_t clen,
                                      const uint8_t *npub,
                                      const uint8_t *k);
void aegis256_mac_init(aegis256_mac_state *st_, const uint8_t *k, const uint8_t *npub);
int aegis256_mac_update(aegis256_mac_state *st_, const uint8_t *m, size_t mlen);
int aegis256_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen);
int aegis256_mac_verify(aegis256_mac_state *st_, const uint8_t *mac, size_t maclen);
void aegis256_mac_reset(aegis256_mac_state *st_);
void aegis256_mac_state_clone(aegis256_mac_state *dst, const aegis256_mac_state *src);

/* aegis256x2.h */
typedef struct aegis256x2_state { uint8_t opaque[320]; } aegis256x2_state;
typedef struct aegis256x2_mac_state { uint8_t opaque[512]; } aegis256x2_mac_state;
size_t aegis256x2_keybytes(void);
size_t aegis256x2_npubbytes(void);
size_t aegis256x2_abytes_min(void);
size_t aegis256x2_abytes_max(void);
size_t aegis256x2_tailbytes_max(void);
int aegis256x2_encrypt_detached(uint8_t *c,
                                uint8_t *mac,
                                size_t maclen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis256x2_decrypt_detached(uint8_t *m,
                                const uint8_t *c,
                                size_t clen,
                                const uint8_t *mac,
                                size_t maclen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis256x2_encrypt(uint8_t *c,
                       size_t maclen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
int aegis256x2_decrypt(uint8_t *m,
                       const uint8_t *c,
                       size_t clen,
                       size_t maclen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
void aegis256x2_state_init(aegis256x2_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis256x2_state_encrypt_update(aegis256x2_state *st_,
                                    uint8_t *c,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis256x2_state_encrypt_final(aegis256x2_state *st_, uint8_t *mac, size_t maclen);
int aegis256x2_state_decrypt_update(aegis256x2_state *st_,
                                    uint8_t *m,
                                    const uint8_t *c,
                                    size_t clen);
int aegis256x2_state_decrypt_final(aegis256x2_state *st_, const uint8_t *mac, size_t maclen);
void aegis256x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
void aegis256x2_stream_xor(uint8_t *out,
                           const uint8_t *in,
                           size_t len,
                           const uint8_t *npub,
                           const uint8_t *k);
void aegis256x2_encrypt_unauthenticated(uint8_t *c,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis256x2_decrypt_unauthenticated(uint8_t *m,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis256x2_mac_init(aegis256x2_mac_state *st_, const uint8_t *k, const uint8_t *npub);
int aegis256x2_mac_update(aegis256x2_mac_state *st_, const uint8_t *m, size_t mlen);
int aegis256x2_mac_final(aegis256x2_mac_state *st_, uint8_t *mac, size_t maclen);
int aegis256x2_mac_verify(aegis256x2_mac_state *st_, const uint8_t *mac, size_t maclen);
void aegis256x2_mac_reset(aegis256x2_mac_state *st_);
void aegis256x2_mac_state_clone(aegis256x2_mac_state *dst, const aegis256x2_mac_state *src);

/* aegis256x4.h */
typedef struct aegis256x4_state { uint8_t opaque[576]; } aegis256x4_state;
typedef struct aegis256x4_mac_state { uint8_t opaque[960]; } aegis256x4_mac_state;
size_t aegis256x4_keybytes(void);
size_t aegis256x4_npubbytes(void);
size_t aegis256x4_abytes_min(void);
size_t aegis256x4_abytes_max(void);
size_t aegis256x4_tailbytes_max(void);
int aegis256x4_encrypt_detached(uint8_t *c,
                                uint8_t *mac,
                                size_t maclen,
                                const uint8_t *m,
                                size_t mlen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis256x4_decrypt_detached(uint8_t *m,
                                const uint8_t *c,
                                size_t clen,
                                const uint8_t *mac,
                                size_t maclen,
                                const uint8_t *ad,
                                size_t adlen,
                                const uint8_t *npub,
                                const uint8_t *k);
int aegis256x4_encrypt(uint8_t *c,
                       size_t maclen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
int aegis256x4_decrypt(uint8_t *m,
                       const uint8_t *c,
                       size_t clen,
                       size_t maclen,
                       const uint8_t *ad,
                       size_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
void aegis256x4_state_init(aegis256x4_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis256x4_state_encrypt_update(aegis256x4_state *st_,
                                    uint8_t *c,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis256x4_state_encrypt_final(aegis256x4_state *st_, uint8_t *mac, size_t maclen);
int aegis256x4_state_decrypt_update(aegis256x4_state *st_,
                                    uint8_t *m,
                                    const uint8_t *c,
                                    size_t clen);
int aegis256x4_state_decrypt_final(aegis256x4_state *st_, const uint8_t *mac, size_t maclen);
void aegis256x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
void aegis256x4_stream_xor(uint8_t *out,
                           const uint8_t *in,
                           size_t len,
                           const uint8_t *npub,
                           const uint8_t *k);
void aegis256x4_encrypt_unauthenticated(uint8_t *c,
                                        const uint8_t *m,
                                        size_t mlen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis256x4_decrypt_unauthenticated(uint8_t *m,
                                        const uint8_t *c,
                                        size_t clen,
                                        const uint8_t *npub,
                                        const uint8_t *k);
void aegis256x4_mac_init(aegis256x4_mac_state *st_, const uint8_t *k, const uint8_t *npub);
int aegis256x4_mac_update(aegis256x4_mac_state *st_, const uint8_t *m, size_t mlen);
int aegis256x4_mac_final(aegis256x4_mac_state *st_, uint8_t *mac, size_t maclen);
int aegis256x4_mac_verify(aegis256x4_mac_state *st_, const uint8_t *mac, size_t maclen);
void aegis256x4_mac_reset(aegis256x4_mac_state *st_);
void aegis256x4_mac_state_clone(aegis256x4_mac_state *dst, const aegis256x4_mac_state *src);

/* aegis_raf.h */
typedef struct aegis_raf_scratch { uint8_t *buf; size_t len; } aegis_raf_scratch;
typedef struct aegis_raf_io { void *user; int (*read_at)(void *user,
                                               uint8_t *buf,
                                               size_t len,
                                               uint64_t off); int (*write_at)(void *user,
                                               const uint8_t *buf,
                                               size_t len,
                                               uint64_t off); int (*get_size)(void *user,
                                               uint64_t *size); int (*set_size)(void *user,
                                               uint64_t size); int (*sync)(void *user); } aegis_raf_io;
typedef struct aegis_raf_rng { void *user; int (*random)(void *user, uint8_t *out, size_t len); } aegis_raf_rng;
typedef struct aegis_raf_merkle_config { int (*hash_leaf)(void *user,
                                              uint8_t *out,
                                              size_t out_len,
                                              const uint8_t *chunk,
                                              size_t chunk_len,
                                              uint64_t chunk_idx); int (*hash_parent)(void *user,
                                              uint8_t *out,
                                              size_t out_len,
                                              const uint8_t *left,
                                              const uint8_t *right,
                                              uint32_t level,
                                              uint64_t node_idx); int (*hash_empty)(void *user,
                                              uint8_t *out,
                                              size_t out_len,
                                              uint32_t level,
                                              uint64_t node_idx); int (*hash_commitment)(void *user,
                                              uint8_t *out,
                                              size_t out_len,
                                              const uint8_t *structural_root,
                                              const uint8_t *ctx,
                                              size_t ctx_len,
                                              uint64_t file_size); void *user; uint8_t *buf; size_t len; uint64_t max_chunks; uint32_t hash_len; } aegis_raf_merkle_config;
typedef struct aegis_raf_config { const aegis_raf_scratch *scratch; const aegis_raf_merkle_config *merkle; uint32_t chunk_size; uint8_t flags; } aegis_raf_config;
typedef struct aegis_raf_info { uint64_t file_size; uint32_t chunk_size; uint8_t alg_id; } aegis_raf_info;
typedef struct aegis128l_raf_ctx { uint8_t opaque[512]; } aegis128l_raf_ctx;
typedef struct aegis128x2_raf_ctx { uint8_t opaque[512]; } aegis128x2_raf_ctx;
typedef struct aegis128x4_raf_ctx { uint8_t opaque[512]; } aegis128x4_raf_ctx;
typedef struct aegis256_raf_ctx { uint8_t opaque[512]; } aegis256_raf_ctx;
typedef struct aegis256x2_raf_ctx { uint8_t opaque[512]; } aegis256x2_raf_ctx;
typedef struct aegis256x4_raf_ctx { uint8_t opaque[512]; } aegis256x4_raf_ctx;
size_t aegis_raf_chunk_min(void);
size_t aegis_raf_chunk_max(void);
size_t aegis_raf_header_size(void);
size_t aegis_raf_scratch_align(void);
int aegis_raf_probe(const aegis_raf_io *io, aegis_raf_info *info);
size_t aegis128l_raf_scratch_size(uint32_t chunk_size);
int aegis128l_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
size_t aegis128x2_raf_scratch_size(uint32_t chunk_size);
int aegis128x2_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
size_t aegis128x4_raf_scratch_size(uint32_t chunk_size);
int aegis128x4_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
size_t aegis256_raf_scratch_size(uint32_t chunk_size);
int aegis256_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
size_t aegis256x2_raf_scratch_size(uint32_t chunk_size);
int aegis256x2_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
size_t aegis256x4_raf_scratch_size(uint32_t chunk_size);
int aegis256x4_raf_scratch_validate(const aegis_raf_scratch *scratch, uint32_t chunk_size);
size_t aegis_raf_merkle_buffer_size(const aegis_raf_merkle_config *cfg);
int aegis_raf_derive_master_key(uint8_t *out,
                                size_t out_len,
                                const uint8_t *master_key,
                                size_t master_key_len,
                                const uint8_t *context,
                                size_t context_len);
int aegis128l_raf_create(aegis128l_raf_ctx *ctx,
                         const aegis_raf_io *io,
                         const aegis_raf_rng *rng,
                         const aegis_raf_config *cfg,
                         const uint8_t *master_key);
int aegis128l_raf_open(aegis128l_raf_ctx *ctx,
                       const aegis_raf_io *io,
                       const aegis_raf_rng *rng,
                       const aegis_raf_config *cfg,
                       const uint8_t *master_key);
int aegis128l_raf_read(aegis128l_raf_ctx *ctx,
                       uint8_t *out,
                       size_t *bytes_read,
                       size_t len,
                       uint64_t offset);
int aegis128l_raf_write(aegis128l_raf_ctx *ctx,
                        size_t *bytes_written,
                        const uint8_t *in,
                        size_t len,
                        uint64_t offset);
int aegis128l_raf_truncate(aegis128l_raf_ctx *ctx, uint64_t size);
int aegis128l_raf_get_size(const aegis128l_raf_ctx *ctx, uint64_t *size);
int aegis128l_raf_sync(aegis128l_raf_ctx *ctx);
void aegis128l_raf_close(aegis128l_raf_ctx *ctx);
int aegis128l_raf_merkle_rebuild(aegis128l_raf_ctx *ctx);
int aegis128l_raf_merkle_verify(aegis128l_raf_ctx *ctx, uint64_t *corrupted_chunk);
int aegis128l_raf_merkle_commitment(const aegis128l_raf_ctx *ctx, uint8_t *out, size_t out_len);
int aegis128x2_raf_create(aegis128x2_raf_ctx *ctx,
                          const aegis_raf_io *io,
                          const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg,
                          const uint8_t *master_key);
int aegis128x2_raf_open(aegis128x2_raf_ctx *ctx,
                        const aegis_raf_io *io,
                        const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg,
                        const uint8_t *master_key);
int aegis128x2_raf_read(aegis128x2_raf_ctx *ctx,
                        uint8_t *out,
                        size_t *bytes_read,
                        size_t len,
                        uint64_t offset);
int aegis128x2_raf_write(aegis128x2_raf_ctx *ctx,
                         size_t *bytes_written,
                         const uint8_t *in,
                         size_t len,
                         uint64_t offset);
int aegis128x2_raf_truncate(aegis128x2_raf_ctx *ctx, uint64_t size);
int aegis128x2_raf_get_size(const aegis128x2_raf_ctx *ctx, uint64_t *size);
int aegis128x2_raf_sync(aegis128x2_raf_ctx *ctx);
void aegis128x2_raf_close(aegis128x2_raf_ctx *ctx);
int aegis128x2_raf_merkle_rebuild(aegis128x2_raf_ctx *ctx);
int aegis128x2_raf_merkle_verify(aegis128x2_raf_ctx *ctx, uint64_t *corrupted_chunk);
int aegis128x2_raf_merkle_commitment(const aegis128x2_raf_ctx *ctx, uint8_t *out, size_t out_len);
int aegis128x4_raf_create(aegis128x4_raf_ctx *ctx,
                          const aegis_raf_io *io,
                          const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg,
                          const uint8_t *master_key);
int aegis128x4_raf_open(aegis128x4_raf_ctx *ctx,
                        const aegis_raf_io *io,
                        const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg,
                        const uint8_t *master_key);
int aegis128x4_raf_read(aegis128x4_raf_ctx *ctx,
                        uint8_t *out,
                        size_t *bytes_read,
                        size_t len,
                        uint64_t offset);
int aegis128x4_raf_write(aegis128x4_raf_ctx *ctx,
                         size_t *bytes_written,
                         const uint8_t *in,
                         size_t len,
                         uint64_t offset);
int aegis128x4_raf_truncate(aegis128x4_raf_ctx *ctx, uint64_t size);
int aegis128x4_raf_get_size(const aegis128x4_raf_ctx *ctx, uint64_t *size);
int aegis128x4_raf_sync(aegis128x4_raf_ctx *ctx);
void aegis128x4_raf_close(aegis128x4_raf_ctx *ctx);
int aegis128x4_raf_merkle_rebuild(aegis128x4_raf_ctx *ctx);
int aegis128x4_raf_merkle_verify(aegis128x4_raf_ctx *ctx, uint64_t *corrupted_chunk);
int aegis128x4_raf_merkle_commitment(const aegis128x4_raf_ctx *ctx, uint8_t *out, size_t out_len);
int aegis256_raf_create(aegis256_raf_ctx *ctx,
                        const aegis_raf_io *io,
                        const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg,
                        const uint8_t *master_key);
int aegis256_raf_open(aegis256_raf_ctx *ctx,
                      const aegis_raf_io *io,
                      const aegis_raf_rng *rng,
                      const aegis_raf_config *cfg,
                      const uint8_t *master_key);
int aegis256_raf_read(aegis256_raf_ctx *ctx,
                      uint8_t *out,
                      size_t *bytes_read,
                      size_t len,
                      uint64_t offset);
int aegis256_raf_write(aegis256_raf_ctx *ctx,
                       size_t *bytes_written,
                       const uint8_t *in,
                       size_t len,
                       uint64_t offset);
int aegis256_raf_truncate(aegis256_raf_ctx *ctx, uint64_t size);
int aegis256_raf_get_size(const aegis256_raf_ctx *ctx, uint64_t *size);
int aegis256_raf_sync(aegis256_raf_ctx *ctx);
void aegis256_raf_close(aegis256_raf_ctx *ctx);
int aegis256_raf_merkle_rebuild(aegis256_raf_ctx *ctx);
int aegis256_raf_merkle_verify(aegis256_raf_ctx *ctx, uint64_t *corrupted_chunk);
int aegis256_raf_merkle_commitment(const aegis256_raf_ctx *ctx, uint8_t *out, size_t out_len);
int aegis256x2_raf_create(aegis256x2_raf_ctx *ctx,
                          const aegis_raf_io *io,
                          const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg,
                          const uint8_t *master_key);
int aegis256x2_raf_open(aegis256x2_raf_ctx *ctx,
                        const aegis_raf_io *io,
                        const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg,
                        const uint8_t *master_key);
int aegis256x2_raf_read(aegis256x2_raf_ctx *ctx,
                        uint8_t *out,
                        size_t *bytes_read,
                        size_t len,
                        uint64_t offset);
int aegis256x2_raf_write(aegis256x2_raf_ctx *ctx,
                         size_t *bytes_written,
                         const uint8_t *in,
                         size_t len,
                         uint64_t offset);
int aegis256x2_raf_truncate(aegis256x2_raf_ctx *ctx, uint64_t size);
int aegis256x2_raf_get_size(const aegis256x2_raf_ctx *ctx, uint64_t *size);
int aegis256x2_raf_sync(aegis256x2_raf_ctx *ctx);
void aegis256x2_raf_close(aegis256x2_raf_ctx *ctx);
int aegis256x2_raf_merkle_rebuild(aegis256x2_raf_ctx *ctx);
int aegis256x2_raf_merkle_verify(aegis256x2_raf_ctx *ctx, uint64_t *corrupted_chunk);
int aegis256x2_raf_merkle_commitment(const aegis256x2_raf_ctx *ctx, uint8_t *out, size_t out_len);
int aegis256x4_raf_create(aegis256x4_raf_ctx *ctx,
                          const aegis_raf_io *io,
                          const aegis_raf_rng *rng,
                          const aegis_raf_config *cfg,
                          const uint8_t *master_key);
int aegis256x4_raf_open(aegis256x4_raf_ctx *ctx,
                        const aegis_raf_io *io,
                        const aegis_raf_rng *rng,
                        const aegis_raf_config *cfg,
                        const uint8_t *master_key);
int aegis256x4_raf_read(aegis256x4_raf_ctx *ctx,
                        uint8_t *out,
                        size_t *bytes_read,
                        size_t len,
                        uint64_t offset);
int aegis256x4_raf_write(aegis256x4_raf_ctx *ctx,
                         size_t *bytes_written,
                         const uint8_t *in,
                         size_t len,
                         uint64_t offset);
int aegis256x4_raf_truncate(aegis256x4_raf_ctx *ctx, uint64_t size);
int aegis256x4_raf_get_size(const aegis256x4_raf_ctx *ctx, uint64_t *size);
int aegis256x4_raf_sync(aegis256x4_raf_ctx *ctx);
void aegis256x4_raf_close(aegis256x4_raf_ctx *ctx);
int aegis256x4_raf_merkle_rebuild(aegis256x4_raf_ctx *ctx);
int aegis256x4_raf_merkle_verify(aegis256x4_raf_ctx *ctx, uint64_t *corrupted_chunk);
int aegis256x4_raf_merkle_commitment(const aegis256x4_raf_ctx *ctx, uint8_t *out, size_t out_len);
