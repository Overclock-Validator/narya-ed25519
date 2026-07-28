/*
 * Copyright 2026 Overclock Validator
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Standalone benchmark driver for the unmodified Firedancer C verifier at
 * commit 3ed37488372b7e50bb03ca30477be48508ee7022.  This file is compiled in
 * the Firedancer checkout and linked to Firedancer's native ballet library;
 * it is not cgo and is not part of Narya's runtime.
 */

#include "src/ballet/fd_ballet.h"
#include "src/ballet/ed25519/fd_ed25519.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_N   64UL
#define MAX_MSG 1232UL

static volatile int bench_sink;

static int
canonical_r_y( uchar const sig[ static 64 ] ) {
  /* Compare low255(sig[0..31]) against p=2^255-19, little endian. */
  static uchar const p[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
  };
  for( int i=31; i>=0; i-- ) {
    uchar x = i==31 ? (uchar)(sig[i] & (uchar)0x7f) : sig[i];
    if( x<p[i] ) return 1;
    if( x>p[i] ) return 0;
  }
  return 0;
}

static int
strict_verify( uchar const * msg,
               ulong         msg_sz,
               uchar const   sig[ static 64 ],
               uchar const   pub[ static 32 ],
               fd_sha512_t * sha ) {
  if( FD_UNLIKELY( !canonical_r_y( sig ) ) ) return FD_ED25519_ERR_SIG;
  return fd_ed25519_verify( msg, msg_sz, sig, pub, sha );
}

static int
strict_batch_shared( uchar const * msg,
                     ulong         msg_sz,
                     uchar const * sigs,
                     uchar const * pubs,
                     fd_sha512_t ** shas,
                     ulong         n ) {
  for( ulong i=0UL; i<n; i++ )
    if( FD_UNLIKELY( !canonical_r_y( sigs+64UL*i ) ) ) return FD_ED25519_ERR_SIG;
  for( ulong off=0UL; off<n; off+=16UL ) {
    uchar width = (uchar)fd_ulong_min( 16UL, n-off );
    int rc = fd_ed25519_verify_batch_single_msg( msg, msg_sz, sigs+64UL*off,
                                                 pubs+32UL*off, shas+off, width );
    if( FD_UNLIKELY( rc!=FD_ED25519_SUCCESS ) ) return rc;
  }
  return FD_ED25519_SUCCESS;
}

static int
strict_loop_distinct( uchar const msgs[ static MAX_N*MAX_MSG ],
                      ulong       msg_sz,
                      uchar const sigs[ static MAX_N*64UL ],
                      uchar const pubs[ static MAX_N*32UL ],
                      fd_sha512_t * sha,
                      ulong       n ) {
  for( ulong i=0UL; i<n; i++ ) {
    int rc = strict_verify( msgs+i*MAX_MSG, msg_sz, sigs+64UL*i, pubs+32UL*i, sha );
    if( FD_UNLIKELY( rc!=FD_ED25519_SUCCESS ) ) return rc;
  }
  return FD_ED25519_SUCCESS;
}

static void
report( char const * kind,
        ulong        msg_sz,
        ulong        n,
        ulong        calls,
        long         elapsed ) {
  ulong  signatures = calls*n;
  double ns_per_call = (double)elapsed/(double)calls;
  double ns_per_sig  = (double)elapsed/(double)signatures;
  printf( "kind=%-22s msg=%4lu n=%2lu calls=%8lu signatures=%9lu ns/op=%12.3f ns/sig=%10.3f\n",
          kind, msg_sz, n, calls, signatures, ns_per_call, ns_per_sig );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  ulong target_sigs = 50000UL;
  if( argc>1 ) target_sigs = strtoul( argv[1], NULL, 10 );
  ulong msg_filter = 0UL;
  ulong width_filter = 0UL;
  if( argc>2 ) msg_filter = strtoul( argv[2], NULL, 10 );
  if( argc>3 ) width_filter = strtoul( argv[3], NULL, 10 );
  if( FD_UNLIKELY( argc>4 ||
                   (msg_filter && msg_filter!=64UL && msg_filter!=200UL && msg_filter!=1232UL) ||
                   (width_filter && width_filter!=1UL && width_filter!=2UL &&
                    width_filter!=3UL && width_filter!=4UL && width_filter!=5UL &&
                    width_filter!=8UL && width_filter!=12UL && width_filter!=16UL &&
                    width_filter!=17UL && width_filter!=32UL && width_filter!=64UL) ) ) {
    fprintf( stderr, "usage: %s [target-signatures [message-bytes [width]]]\n", argv[0] );
    fd_halt();
    return 2;
  }

  static uchar shared_msg[MAX_MSG];
  static uchar distinct_msgs[MAX_N*MAX_MSG];
  static uchar shared_sigs[MAX_N*64UL];
  static uchar distinct_sigs[MAX_N*64UL];
  static uchar pubs[MAX_N*32UL];
  static uchar privs[MAX_N*32UL];
  static fd_sha512_t * shas[MAX_N];

  fd_sha512_t sha_mem[1];
  fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( sha_mem ) );
  for( ulong j=0UL; j<MAX_MSG; j++ ) shared_msg[j] = (uchar)(j*131UL + 17UL);
  for( ulong i=0UL; i<MAX_N; i++ ) {
    shas[i] = sha;
    for( ulong j=0UL; j<32UL; j++ ) privs[32UL*i+j] = (uchar)(11UL + 29UL*i + 7UL*j);
    for( ulong j=0UL; j<MAX_MSG; j++ )
      distinct_msgs[MAX_MSG*i+j] = (uchar)(shared_msg[j] ^ (uchar)(17UL*i + j/17UL));
    fd_ed25519_public_from_private( pubs+32UL*i, privs+32UL*i, sha );
  }

  static ulong const msg_sizes[] = { 64UL, 200UL, 1232UL };
  static ulong const widths[] = { 1UL, 2UL, 3UL, 4UL, 5UL, 8UL, 12UL, 16UL, 17UL, 32UL, 64UL };
  for( ulong mi=0UL; mi<3UL; mi++ ) {
    ulong msg_sz = msg_sizes[mi];
    if( msg_filter && msg_sz!=msg_filter ) continue;
    for( ulong i=0UL; i<MAX_N; i++ ) {
      fd_ed25519_sign( shared_sigs+64UL*i, shared_msg, msg_sz,
                       pubs+32UL*i, privs+32UL*i, sha );
      fd_ed25519_sign( distinct_sigs+64UL*i, distinct_msgs+MAX_MSG*i, msg_sz,
                       pubs+32UL*i, privs+32UL*i, sha );
    }

    for( ulong wi=0UL; wi<sizeof(widths)/sizeof(widths[0]); wi++ ) {
      ulong n = widths[wi];
      if( width_filter && n!=width_filter ) continue;
      ulong calls = fd_ulong_max( 10UL, target_sigs/n );
      long then = fd_log_wallclock();
      int result = 0;
      for( ulong rem=calls; rem; rem-- )
        result |= strict_batch_shared( shared_msg, msg_sz, shared_sigs, pubs, shas, n );
      long elapsed = fd_log_wallclock()-then;
      bench_sink |= result;
      report( "fd-strict-shared", msg_sz, n, calls, elapsed );
    }

    for( ulong wi=0UL; wi<sizeof(widths)/sizeof(widths[0]); wi++ ) {
      ulong n = widths[wi];
      if( width_filter && n!=width_filter ) continue;
      ulong calls = fd_ulong_max( 10UL, target_sigs/n );
      long then = fd_log_wallclock();
      int result = 0;
      for( ulong rem=calls; rem; rem-- )
        result |= strict_loop_distinct( distinct_msgs, msg_sz, distinct_sigs, pubs, sha, n );
      long elapsed = fd_log_wallclock()-then;
      bench_sink |= result;
      report( "fd-strict-distinct", msg_sz, n, calls, elapsed );
    }

    if( msg_sz==200UL ) {
      static ulong const invalid_widths[] = { 1UL, 8UL, 64UL };
      static uchar bad_s_sigs[MAX_N*64UL];
      static uchar late_shared_msg[MAX_MSG];
      static uchar late_shared_sigs[MAX_N*64UL];
      static uchar late_distinct_msgs[MAX_N*MAX_MSG];

      fd_memcpy( bad_s_sigs, shared_sigs, sizeof(bad_s_sigs) );
      fd_memset( bad_s_sigs+32UL, 0xff, 32UL );
      fd_memcpy( late_shared_msg, shared_msg, sizeof(late_shared_msg) );
      late_shared_msg[0] ^= (uchar)1;
      for( ulong i=0UL; i<MAX_N; i++ )
        fd_ed25519_sign( late_shared_sigs+64UL*i, late_shared_msg, msg_sz,
                         pubs+32UL*i, privs+32UL*i, sha );
      fd_memcpy( late_distinct_msgs, distinct_msgs, sizeof(late_distinct_msgs) );

      for( ulong wi=0UL; wi<sizeof(invalid_widths)/sizeof(invalid_widths[0]); wi++ ) {
        ulong n = invalid_widths[wi];
        if( width_filter && n!=width_filter ) continue;
        ulong calls = fd_ulong_max( 100UL, target_sigs/n );
        int unexpected = 0;
        long then = fd_log_wallclock();
        for( ulong rem=calls; rem; rem-- )
          unexpected |= strict_batch_shared( shared_msg, msg_sz, bad_s_sigs,
                                             pubs, shas, n )==FD_ED25519_SUCCESS;
        long elapsed = fd_log_wallclock()-then;
        bench_sink |= unexpected;
        report( "fd-batch-badS-first", msg_sz, n, calls, elapsed );

        /* All earlier lanes verify for late_shared_msg; only the final lane
           carries the signature for shared_msg and reaches an equation miss. */
        fd_memcpy( late_shared_sigs+64UL*(n-1UL), shared_sigs+64UL*(n-1UL), 64UL );
        unexpected = 0;
        then = fd_log_wallclock();
        for( ulong rem=calls; rem; rem-- )
          unexpected |= strict_batch_shared( late_shared_msg, msg_sz, late_shared_sigs,
                                             pubs, shas, n )==FD_ED25519_SUCCESS;
        elapsed = fd_log_wallclock()-then;
        bench_sink |= unexpected;
        report( "fd-batch-badmsg-last", msg_sz, n, calls, elapsed );

        fd_memcpy( bad_s_sigs, distinct_sigs, sizeof(bad_s_sigs) );
        fd_memset( bad_s_sigs+32UL, 0xff, 32UL );
        unexpected = 0;
        then = fd_log_wallclock();
        for( ulong rem=calls; rem; rem-- )
          unexpected |= strict_loop_distinct( distinct_msgs, msg_sz, bad_s_sigs,
                                              pubs, sha, n )==FD_ED25519_SUCCESS;
        elapsed = fd_log_wallclock()-then;
        bench_sink |= unexpected;
        report( "fd-loop-badS-first", msg_sz, n, calls, elapsed );

        /* Only the final message is changed, so the ordinary verify loop
           performs n-1 valid verifies and one full equation failure. */
        late_distinct_msgs[MAX_MSG*(n-1UL)] ^= (uchar)1;
        unexpected = 0;
        then = fd_log_wallclock();
        for( ulong rem=calls; rem; rem-- )
          unexpected |= strict_loop_distinct( late_distinct_msgs, msg_sz,
                                              distinct_sigs, pubs, sha, n )==FD_ED25519_SUCCESS;
        elapsed = fd_log_wallclock()-then;
        bench_sink |= unexpected;
        report( "fd-loop-badmsg-last", msg_sz, n, calls, elapsed );
        late_distinct_msgs[MAX_MSG*(n-1UL)] ^= (uchar)1;

        /* Restore the two buffers changed for this width before the next. */
        fd_ed25519_sign( late_shared_sigs+64UL*(n-1UL), late_shared_msg, msg_sz,
                         pubs+32UL*(n-1UL), privs+32UL*(n-1UL), sha );
        fd_memcpy( bad_s_sigs, shared_sigs, sizeof(bad_s_sigs) );
        fd_memset( bad_s_sigs+32UL, 0xff, 32UL );
      }
    }
  }

  fd_sha512_delete( fd_sha512_leave( sha ) );
  fd_halt();
  return !!bench_sink;
}
