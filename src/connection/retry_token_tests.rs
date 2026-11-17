// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/gpl-3.0.html>
//
// Full details available at https://saorsalabs.com/licenses

//! A peer-supplied Initial token must never break the client's packet builder
//! (the RUSTSEC-2026-0524 shape in quinn-proto).
//!
//! The client puts the token from a Retry, or one cached from NEW_TOKEN, in the
//! header of every Initial. A token that leaves no room in a 1200-byte Initial
//! made `PacketBuilder::new` compute a minimum size above the maximum, which
//! only a `debug_assert` checked: a debug build panicked there, and a release
//! build went on with an impossible size (in quinn-proto it tried an allocation
//! of over 10 GiB; ant-quic's release behaviour was not measured). Anyone who
//! sees the client's first Initial can forge the Retry.

use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};

use super::{
    ConnectionSide,
    pqc_mtu_regression_tests::{client_config, server_config},
};
use crate::{
    ClientConfig, Connection, ConnectionError, ConnectionId, DEFAULT_SUPPORTED_VERSIONS,
    EndpointConfig, Event, Instant, TransportErrorCode,
    endpoint::{DatagramEvent, Endpoint},
    packet::{FixedLengthConnectionIdParser, Header, ProtectedHeader, ProtectedInitialHeader},
};
use crate::{
    frame::{self, Frame},
    packet::{PartialDecode, SpaceId},
};

const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

fn connect(config: ClientConfig) -> (Endpoint, Connection) {
    let mut endpoint = Endpoint::new(Arc::new(EndpointConfig::default()), None, true, None);
    let (_, conn) = endpoint
        .connect(Instant::now(), config, SERVER_ADDR, "localhost")
        .unwrap();
    (endpoint, conn)
}

fn initial_header(datagram: &[u8]) -> ProtectedInitialHeader {
    let header = ProtectedHeader::decode(
        &mut Cursor::new(BytesMut::from(datagram)),
        &FixedLengthConnectionIdParser::new(0),
        DEFAULT_SUPPORTED_VERSIONS,
        false,
    )
    .unwrap();
    let ProtectedHeader::Initial(initial) = header else {
        panic!("expected an Initial packet");
    };
    initial
}

fn client_token(conn: &Connection) -> Bytes {
    let ConnectionSide::Client { ref token, .. } = conn.side else {
        panic!("expected a client connection");
    };
    token.clone()
}

fn lost_to_protocol_violation(conn: &mut Connection) -> bool {
    std::iter::from_fn(|| conn.poll()).any(|event| {
        matches!(
            event,
            Event::ConnectionLost {
                reason: ConnectionError::TransportError(ref err)
            } if err.code == TransportErrorCode::PROTOCOL_VIOLATION
        )
    })
}

/// Send a validly tagged Retry carrying `token_len` bytes of token to a client
/// that has sent its first Initial.
fn deliver_retry(token_len: usize) -> (Endpoint, Connection, Instant) {
    let (mut endpoint, mut conn) = connect(client_config());
    let now = Instant::now();
    let mut buf = Vec::new();
    let _ = conn.poll_transmit(now, 1, &mut buf).unwrap();
    let initial = initial_header(&buf);

    let header = Header::Retry {
        src_cid: ConnectionId::new(&[1; 20]),
        dst_cid: initial.src_cid,
        version: initial.version,
    };
    let mut retry = Vec::new();
    header.encode(&mut retry);
    retry.resize(retry.len() + token_len, 0);
    let tag = server_config()
        .crypto
        .retry_tag(initial.version, &initial.dst_cid, &retry);
    retry.extend_from_slice(&tag);

    let Some(DatagramEvent::ConnectionEvent(_, event)) = endpoint.handle(
        now,
        SERVER_ADDR,
        None,
        None,
        BytesMut::from(&retry[..]),
        &mut buf,
    ) else {
        panic!("the Retry must reach the client connection");
    };
    conn.handle_event(event);
    (endpoint, conn, now)
}

#[test]
fn a_retry_token_that_fits_is_used() {
    let (_endpoint, mut conn, now) = deliver_retry(64);
    assert_eq!(client_token(&conn).len(), 64);
    let mut buf = Vec::new();
    let _ = conn
        .poll_transmit(now, 1, &mut buf)
        .expect("the client resends its Initial with the token");
    assert!(buf.len() <= crate::MIN_INITIAL_SIZE as usize);
    assert_eq!(initial_header(&buf).token_pos.len(), 64);
}

#[test]
fn an_oversized_retry_token_is_dropped() {
    for token_len in [super::MAX_RETRY_TOKEN_LEN + 1, 1000, 1140, 1200, 4000] {
        let (_endpoint, mut conn, now) = deliver_retry(token_len);
        assert!(
            client_token(&conn).is_empty(),
            "token {token_len}: an oversized Retry must not be stored"
        );
        assert!(conn.retry_src_cid.is_none(), "token {token_len}");
        assert!(!conn.is_closed(), "token {token_len}");

        // The client still waits for the real server, and its next Initial
        // carries no token.
        let deadline = conn.poll_timeout().expect("the Initial is still in flight");
        assert!(deadline > now);
        conn.handle_timeout(deadline);
        let mut buf = Vec::new();
        let _ = conn
            .poll_transmit(deadline, 1, &mut buf)
            .expect("the client retransmits its Initial");
        assert!(buf.len() <= crate::MIN_INITIAL_SIZE as usize);
        assert!(
            initial_header(&buf).token_pos.is_empty(),
            "token {token_len}"
        );
        assert!(!lost_to_protocol_violation(&mut conn), "token {token_len}");
    }
}

#[test]
fn a_retry_token_at_the_cap_is_used() {
    let (_endpoint, mut conn, now) = deliver_retry(super::MAX_RETRY_TOKEN_LEN);
    assert_eq!(client_token(&conn).len(), super::MAX_RETRY_TOKEN_LEN);
    let mut buf = Vec::new();
    let _ = conn
        .poll_transmit(now, 1, &mut buf)
        .expect("the client resends its Initial with the token");
    assert!(buf.len() <= crate::MIN_INITIAL_SIZE as usize);
    assert_eq!(
        initial_header(&buf).token_pos.len(),
        super::MAX_RETRY_TOKEN_LEN
    );
}

/// A cached NEW_TOKEN token also came from the peer. One that leaves no room
/// for frames closes the connection instead of breaking the builder.
#[test]
fn an_oversized_cached_token_closes_the_connection() {
    for (token_len, mtu, fits) in [
        (0, 1200, true),
        (512, 1200, true),
        (1119, 1200, true),
        (1120, 1200, false),
        (1140, 1200, false),
        (1200, 1200, false),
        (4000, 1200, false),
        (1200, 1500, true),
    ] {
        let mut config = client_config();
        let mut transport = crate::TransportConfig::default();
        transport.initial_mtu(mtu);
        config.transport_config(Arc::new(transport));
        config
            .token_store
            .insert("localhost", vec![0; token_len].into());
        let (_endpoint, mut conn) = connect(config);
        let now = Instant::now();
        let mut buf = Vec::new();
        assert_eq!(
            conn.poll_transmit(now, 1, &mut buf).is_some(),
            fits,
            "token {token_len}, MTU {mtu}"
        );
        if fits {
            assert!(
                buf.len() <= usize::from(mtu),
                "token {token_len}, MTU {mtu}"
            );
            assert_eq!(initial_header(&buf).token_pos.len(), token_len);
            assert!(conn.stats().frame_tx.crypto > 0);
        } else {
            assert!(buf.is_empty(), "token {token_len}");
            assert!(
                lost_to_protocol_violation(&mut conn),
                "token {token_len}: the connection must close with PROTOCOL_VIOLATION"
            );
            assert!(conn.poll_transmit(now, 1, &mut buf).is_none());
            assert!(buf.is_empty());
        }
    }
}

/// With a long cached token, an Initial that closes the connection drops its
/// ACKs when they would crowd out CONNECTION_CLOSE.
#[test]
fn a_long_initial_token_leaves_room_for_close() {
    // A 16-range ACK is 35 bytes and CONNECTION_CLOSE needs 25: with a 1084-byte
    // token both just fit.
    for (token_len, ack_fits) in [
        (0, true),
        (1000, true),
        (1084, true),
        (1085, false),
        (1100, false),
        (1119, false),
    ] {
        let config = client_config();
        config
            .token_store
            .insert("localhost", vec![0; token_len].into());
        let (_endpoint, mut conn) = connect(config);
        let now = Instant::now();
        let keys = conn
            .crypto
            .initial_keys(&conn.initial_dst_cid, crate::Side::Server);
        let space = &mut conn.spaces[SpaceId::Initial];
        for pn in (0..32).step_by(2) {
            space.pending_acks.insert_one(pn, now);
            space.dedup.insert(pn);
            space
                .pending_acks
                .packet_received(now, pn, true, &space.dedup);
        }
        conn.close(now, 0u32.into(), Bytes::new());
        let mut buf = Vec::new();
        let _ = conn
            .poll_transmit(now, 1, &mut buf)
            .expect("the close goes out");
        assert!(
            buf.len() <= crate::MIN_INITIAL_SIZE as usize,
            "token {token_len}"
        );

        let (packet, rest) = PartialDecode::new(
            BytesMut::from(&buf[..]),
            &FixedLengthConnectionIdParser::new(0),
            DEFAULT_SUPPORTED_VERSIONS,
            false,
        )
        .unwrap();
        assert!(rest.is_none());
        let mut packet = packet.finish(Some(&*keys.header.remote)).unwrap();
        keys.packet
            .remote
            .decrypt(0, &packet.header_data, &mut packet.payload)
            .unwrap();
        let frames: Vec<Frame> = frame::Iter::new(packet.payload.freeze())
            .unwrap()
            .map(Result::unwrap)
            .filter(|frame| !matches!(frame, Frame::Padding))
            .collect();
        let acks = frames
            .iter()
            .filter(|frame| matches!(frame, Frame::Ack(_)))
            .count();
        assert_eq!(acks, usize::from(ack_fits), "token {token_len}");
        assert_eq!(conn.stats().frame_tx.acks, acks as u64, "token {token_len}");
        assert!(
            matches!(frames.last(), Some(Frame::Close(_))),
            "token {token_len}: {frames:?}"
        );
    }
}
