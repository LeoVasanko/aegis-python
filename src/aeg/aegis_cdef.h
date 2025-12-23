/* This file is generated with tools/generate.py. Do not edit. */

typedef unsigned char uint8_t;
typedef unsigned long size_t;

/* aegis.h */
int aegis_init(void);
int aegis_verify_16(const uint8_t *x, const uint8_t *y) ;
int aegis_verify_32(const uint8_t *x, const uint8_t *y) ;

/* aegis128l.h */
typedef struct aegis128l_state { ...; } aegis128l_state;
typedef struct aegis128l_mac_state { ...; } aegis128l_mac_state;
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
                               const uint8_t *k) ;
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
                      const uint8_t *k) ;
void aegis128l_state_init(aegis128l_state *st_,
                          const uint8_t *ad,
                          size_t adlen,
                          const uint8_t *npub,
                          const uint8_t *k);
int aegis128l_state_encrypt_update(aegis128l_state *st_,
                                   uint8_t *c,
                                   size_t clen_max,
                                   size_t *written,
                                   const uint8_t *m,
                                   size_t mlen);
int aegis128l_state_encrypt_detached_final(aegis128l_state *st_,
                                           uint8_t *c,
                                           size_t clen_max,
                                           size_t *written,
                                           uint8_t *mac,
                                           size_t maclen);
int aegis128l_state_encrypt_final(aegis128l_state *st_,
                                  uint8_t *c,
                                  size_t clen_max,
                                  size_t *written,
                                  size_t maclen);
int aegis128l_state_decrypt_detached_update(aegis128l_state *st_,
                                            uint8_t *m,
                                            size_t mlen_max,
                                            size_t *written,
                                            const uint8_t *c,
                                            size_t clen) ;
int aegis128l_state_decrypt_detached_final(aegis128l_state *st_,
                                           uint8_t *m,
                                           size_t mlen_max,
                                           size_t *written,
                                           const uint8_t *mac,
                                           size_t maclen) ;
void aegis128l_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
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
typedef struct aegis128x2_state { ...; } aegis128x2_state;
typedef struct aegis128x2_mac_state { ...; } aegis128x2_mac_state;
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
                                const uint8_t *k) ;
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
                       const uint8_t *k) ;
void aegis128x2_state_init(aegis128x2_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis128x2_state_encrypt_update(aegis128x2_state *st_,
                                    uint8_t *c,
                                    size_t clen_max,
                                    size_t *written,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis128x2_state_encrypt_detached_final(aegis128x2_state *st_,
                                            uint8_t *c,
                                            size_t clen_max,
                                            size_t *written,
                                            uint8_t *mac,
                                            size_t maclen);
int aegis128x2_state_encrypt_final(aegis128x2_state *st_,
                                   uint8_t *c,
                                   size_t clen_max,
                                   size_t *written,
                                   size_t maclen);
int aegis128x2_state_decrypt_detached_update(aegis128x2_state *st_,
                                             uint8_t *m,
                                             size_t mlen_max,
                                             size_t *written,
                                             const uint8_t *c,
                                             size_t clen) ;
int aegis128x2_state_decrypt_detached_final(aegis128x2_state *st_,
                                            uint8_t *m,
                                            size_t mlen_max,
                                            size_t *written,
                                            const uint8_t *mac,
                                            size_t maclen) ;
void aegis128x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
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
typedef struct aegis128x4_state { ...; } aegis128x4_state;
typedef struct aegis128x4_mac_state { ...; } aegis128x4_mac_state;
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
                                const uint8_t *k) ;
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
                       const uint8_t *k) ;
void aegis128x4_state_init(aegis128x4_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis128x4_state_encrypt_update(aegis128x4_state *st_,
                                    uint8_t *c,
                                    size_t clen_max,
                                    size_t *written,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis128x4_state_encrypt_detached_final(aegis128x4_state *st_,
                                            uint8_t *c,
                                            size_t clen_max,
                                            size_t *written,
                                            uint8_t *mac,
                                            size_t maclen);
int aegis128x4_state_encrypt_final(aegis128x4_state *st_,
                                   uint8_t *c,
                                   size_t clen_max,
                                   size_t *written,
                                   size_t maclen);
int aegis128x4_state_decrypt_detached_update(aegis128x4_state *st_,
                                             uint8_t *m,
                                             size_t mlen_max,
                                             size_t *written,
                                             const uint8_t *c,
                                             size_t clen) ;
int aegis128x4_state_decrypt_detached_final(aegis128x4_state *st_,
                                            uint8_t *m,
                                            size_t mlen_max,
                                            size_t *written,
                                            const uint8_t *mac,
                                            size_t maclen) ;
void aegis128x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
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
typedef struct aegis256_state { ...; } aegis256_state;
typedef struct aegis256_mac_state { ...; } aegis256_mac_state;
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
                              const uint8_t *k) ;
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
                     const uint8_t *k) ;
void aegis256_state_init(aegis256_state *st_,
                         const uint8_t *ad,
                         size_t adlen,
                         const uint8_t *npub,
                         const uint8_t *k);
int aegis256_state_encrypt_update(aegis256_state *st_,
                                  uint8_t *c,
                                  size_t clen_max,
                                  size_t *written,
                                  const uint8_t *m,
                                  size_t mlen);
int aegis256_state_encrypt_detached_final(aegis256_state *st_,
                                          uint8_t *c,
                                          size_t clen_max,
                                          size_t *written,
                                          uint8_t *mac,
                                          size_t maclen);
int aegis256_state_encrypt_final(aegis256_state *st_,
                                 uint8_t *c,
                                 size_t clen_max,
                                 size_t *written,
                                 size_t maclen);
int aegis256_state_decrypt_detached_update(aegis256_state *st_,
                                           uint8_t *m,
                                           size_t mlen_max,
                                           size_t *written,
                                           const uint8_t *c,
                                           size_t clen) ;
int aegis256_state_decrypt_detached_final(aegis256_state *st_,
                                          uint8_t *m,
                                          size_t mlen_max,
                                          size_t *written,
                                          const uint8_t *mac,
                                          size_t maclen) ;
void aegis256_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
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
typedef struct aegis256x2_state { ...; } aegis256x2_state;
typedef struct aegis256x2_mac_state { ...; } aegis256x2_mac_state;
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
                                const uint8_t *k) ;
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
                       const uint8_t *k) ;
void aegis256x2_state_init(aegis256x2_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis256x2_state_encrypt_update(aegis256x2_state *st_,
                                    uint8_t *c,
                                    size_t clen_max,
                                    size_t *written,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis256x2_state_encrypt_detached_final(aegis256x2_state *st_,
                                            uint8_t *c,
                                            size_t clen_max,
                                            size_t *written,
                                            uint8_t *mac,
                                            size_t maclen);
int aegis256x2_state_encrypt_final(aegis256x2_state *st_,
                                   uint8_t *c,
                                   size_t clen_max,
                                   size_t *written,
                                   size_t maclen);
int aegis256x2_state_decrypt_detached_update(aegis256x2_state *st_,
                                             uint8_t *m,
                                             size_t mlen_max,
                                             size_t *written,
                                             const uint8_t *c,
                                             size_t clen) ;
int aegis256x2_state_decrypt_detached_final(aegis256x2_state *st_,
                                            uint8_t *m,
                                            size_t mlen_max,
                                            size_t *written,
                                            const uint8_t *mac,
                                            size_t maclen) ;
void aegis256x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
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
typedef struct aegis256x4_state { ...; } aegis256x4_state;
typedef struct aegis256x4_mac_state { ...; } aegis256x4_mac_state;
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
                                const uint8_t *k) ;
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
                       const uint8_t *k) ;
void aegis256x4_state_init(aegis256x4_state *st_,
                           const uint8_t *ad,
                           size_t adlen,
                           const uint8_t *npub,
                           const uint8_t *k);
int aegis256x4_state_encrypt_update(aegis256x4_state *st_,
                                    uint8_t *c,
                                    size_t clen_max,
                                    size_t *written,
                                    const uint8_t *m,
                                    size_t mlen);
int aegis256x4_state_encrypt_detached_final(aegis256x4_state *st_,
                                            uint8_t *c,
                                            size_t clen_max,
                                            size_t *written,
                                            uint8_t *mac,
                                            size_t maclen);
int aegis256x4_state_encrypt_final(aegis256x4_state *st_,
                                   uint8_t *c,
                                   size_t clen_max,
                                   size_t *written,
                                   size_t maclen);
int aegis256x4_state_decrypt_detached_update(aegis256x4_state *st_,
                                             uint8_t *m,
                                             size_t mlen_max,
                                             size_t *written,
                                             const uint8_t *c,
                                             size_t clen) ;
int aegis256x4_state_decrypt_detached_final(aegis256x4_state *st_,
                                            uint8_t *m,
                                            size_t mlen_max,
                                            size_t *written,
                                            const uint8_t *mac,
                                            size_t maclen) ;
void aegis256x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
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
