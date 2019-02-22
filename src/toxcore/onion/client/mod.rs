//! Onion client implementation.

mod nodes_pool;
mod onion_path;
mod paths_pool;

use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use failure::Fail;
use futures::{Future, Stream, future, stream};
use futures::future::Either;
use futures::sync::mpsc;
use parking_lot::Mutex;
use tokio::timer::Interval;

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::packed_node::PackedNode;
use crate::toxcore::dht::packet::*;
use crate::toxcore::dht::request_queue::RequestQueue;
use crate::toxcore::dht::server::{Server as DhtServer};
use crate::toxcore::dht::kbucket::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::ip_port::*;
use crate::toxcore::onion::client::onion_path::*;
use crate::toxcore::onion::client::paths_pool::*;
use crate::toxcore::onion::onion_announce::initial_ping_id;
use crate::toxcore::onion::packet::*;
use crate::toxcore::packed_node::*;
use crate::toxcore::tcp::client::{Connections as TcpConnections};
use crate::toxcore::time::*;

/// Shorthand for the transmit half of the message channel for sending DHT
/// `PublicKey` when it gets known. The first key is a long term key, the second
/// key is a DHT key.
type DhtPkTx = mpsc::UnboundedSender<(PublicKey, PublicKey)>;

/// Number of friend's close nodes to store.
const MAX_ONION_FRIEND_NODES: u8 = 8;

/// Number of nodes to announce ourselves to.
const MAX_ONION_ANNOUNCE_NODES: u8 = 12;

/// Timeout for onion announce packets.
const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many attempts to reach a node we should make.
const ONION_NODE_MAX_PINGS: u32 = 3;

/// How often to ping a node (announce or friend searching).
const ONION_NODE_PING_INTERVAL: u64 = 15;

/// How often we should announce ourselves to a node we are not announced to.
const ANNOUNCE_INTERVAL_NOT_ANNOUNCED: u64 = 3;

/// How often we should announce ourselves to a node we are announced to.
const ANNOUNCE_INTERVAL_ANNOUNCED: u64 = ONION_NODE_PING_INTERVAL;

/// How often we should announce ourselves to a node we are announced to when
/// it's considered stable.
const ANNOUNCE_INTERVAL_STABLE: u64 = ONION_NODE_PING_INTERVAL * 8;

/// How often we should search a friend.
const ANNOUNCE_FRIEND: u64 = ONION_NODE_PING_INTERVAL * 6;

/// How often we should search a friend right after it was added to the friends
/// list.
const ANNOUNCE_FRIEND_BEGINNING: u64 = 3;

/// After this amount of searches we switch from `ANNOUNCE_FRIEND_BEGINNING`
/// to `ANNOUNCE_FRIEND` interval.
const SEARCH_COUNT_FRIEND_ANNOUNCE_BEGINNING: u32 = 17;

/// Longer we didn't see a friend less often we will look for him. This const
/// defines proportion between the search interval and the time we didn't see a
/// friend.
const ONION_FRIEND_BACKOFF_FACTOR: u32 = 4;

/// Maximum interval for friends searching.
const ONION_FRIEND_MAX_PING_INTERVAL: u64 = MAX_ONION_FRIEND_NODES as u64 * 60 * 5;

/// After this time since last unsuccessful ping (and when ping attempts are
/// exhausted) node is considered timed out.
const ONION_NODE_TIMEOUT: u64 = ONION_NODE_PING_INTERVAL;

/// After this interval since creation node is considered stable.
pub(crate) const TIME_TO_STABLE: u64 = ONION_NODE_PING_INTERVAL * 6;

/// The interval in seconds at which to tell our friends our DHT `PublicKey`
/// via onion.
const ONION_DHTPK_SEND_INTERVAL: u64 = 30;

/// The interval in seconds at which to tell our friends our DHT `PublicKey`
/// via DHT request.
const DHT_DHTPK_SEND_INTERVAL: u64 = 20;

const MIN_NODE_PING_TIME: u64 = 10;

/// Friend related data stored in the onion client.
#[derive(Clone, Debug)]
struct OnionFriend {
    /// Friend's long term `PublicKey`.
    real_pk: PublicKey,
    /// Friend's DHT `PublicKey` if it's known.
    dht_pk: Option<PublicKey>,
    /// Temporary `PublicKey` that should be used to encrypt search requests for
    /// this friend.
    temporary_pk: PublicKey,
    /// Temporary `SecretKey` that should be used to encrypt search requests for
    /// this friend.
    temporary_sk: SecretKey,
    /// List of nodes close to friend's long term `PublicKey`.
    close_nodes: Kbucket<OnionNode>,
    /// `no_reply` from last DHT `PublicKey` announce packet used to prevent
    /// reply attacks.
    last_no_reply: u64,
    /// Time when our DHT `PublicKey` was sent to this friend via onion last
    /// time.
    last_dht_pk_onion_sent: Option<Instant>,
    /// Time when our DHT `PublicKey` was sent to this friend via DHT request
    /// last time.
    last_dht_pk_dht_sent: Option<Instant>,
    /// How many times we sent search requests to friend's close nodes.
    search_count: u32,
    /// Time when this friend was seen online last time
    last_seen: Option<Instant>,
}

impl OnionFriend {
    /// Create new `OnionFriend`.
    pub fn new(real_pk: PublicKey) -> Self {
        let (temporary_pk, temporary_sk) = gen_keypair();
        OnionFriend {
            real_pk,
            dht_pk: None,
            temporary_pk,
            temporary_sk,
            close_nodes: Kbucket::new(MAX_ONION_FRIEND_NODES),
            last_no_reply: 0,
            last_dht_pk_onion_sent: None,
            last_dht_pk_dht_sent: None,
            search_count: 0,
            last_seen: None,
        }
    }
}

/// Type for onion close nodes.
#[derive(Clone, Debug)]
struct OnionNode {
    /// Node's `PublicKey`.
    pk: PublicKey,
    /// Node's IP address.
    saddr: SocketAddr,
    /// Path used to send packets to this node.
    path_id: OnionPathId,
    /// Ping id that should be used to announce to this node.
    ping_id: Option<sha256::Digest>,
    /// Data `PublicKey` that should be used to send data packets to our friend
    /// through this node.
    data_pk: Option<PublicKey>,
    /// Number of announce requests sent to this node without any response.
    /// Resets to 0 after receiving a response.
    unsuccessful_pings: u32,
    /// Time when this node was added to close nodes list.
    added_time: Instant,
    /// Time when the last announce packet was sent to this node.
    ping_time: Instant,
    /// Time when we received the last response from this node.
    response_time: Instant,
    /// Announce status from last response from this node.
    announce_status: AnnounceStatus,
}

impl HasPK for OnionNode {
    fn pk(&self) -> PublicKey {
        self.pk
    }
}

impl KbucketNode for OnionNode {
    type NewNode = OnionNode;
    type CheckNode = PackedNode;

    fn is_outdated(&self, other: &PackedNode) -> bool {
        self.saddr != other.saddr
    }
    fn update(&mut self, other: &OnionNode) {
        self.saddr = other.saddr;
        self.path_id = other.path_id;
        self.ping_id = other.ping_id.or(self.ping_id);
        self.data_pk = other.data_pk.or(self.data_pk);
        self.response_time = clock_now();
        self.announce_status = other.announce_status;
    }
    fn is_evictable(&self) -> bool {
        self.is_timed_out()
    }
}

impl OnionNode {
    /// Check if the next ping attempt is the last one.
    pub fn is_last_ping_attempt(&self) -> bool {
        self.unsuccessful_pings == ONION_NODE_MAX_PINGS - 1
    }

    /// Check if ping attempts to this node are exhausted.
    pub fn is_ping_attempts_exhausted(&self) -> bool {
        self.unsuccessful_pings >= ONION_NODE_MAX_PINGS
    }

    /// Check if this node is timed out.
    pub fn is_timed_out(&self) -> bool {
        self.is_ping_attempts_exhausted() &&
            clock_elapsed(self.ping_time) >= Duration::from_secs(ONION_NODE_TIMEOUT)
    }

    /// Node is considered stable after `TIME_TO_STABLE` seconds since it was
    /// added to a close list if it responses to our requests.
    pub fn is_stable(&self) -> bool {
        clock_elapsed(self.added_time) >= Duration::from_secs(TIME_TO_STABLE) &&
            (self.unsuccessful_pings == 0 ||
                 clock_elapsed(self.ping_time) < Duration::from_secs(ONION_NODE_TIMEOUT))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AnnounceRequestData {
    /// `PublicKey` of the node to which we sent a packet.
    pk: PublicKey,
    /// IP address of the node to which we sent a packet.
    saddr: SocketAddr,
    /// Path used to send announce request packet.
    path_id: OnionPathId,
    /// Friend's long term `PublicKey` if announce request was searching
    /// request.
    friend_pk: Option<PublicKey>,
}

/// Announce packet data that doesn't depend on destination node.
#[derive(Clone, Debug, Eq, PartialEq)]
struct AnnouncePacketData<'a> {
    /// `SecretKey` used to encrypt and decrypt announce packets.
    packet_sk: &'a SecretKey,
    /// `PublicKey` used to encrypt and decrypt announce packets.
    packet_pk: PublicKey,
    /// Key that should be used to search close nodes.
    search_pk: PublicKey,
    /// `PublicKey` key that should be used to send data packets to us.
    data_pk: Option<PublicKey>,
}

impl<'a> AnnouncePacketData<'a> {
    /// Create `InnerOnionAnnounceRequest`.
    pub fn request(&self, node_pk: &PublicKey, ping_id: Option<sha256::Digest>, request_id: u64) -> InnerOnionAnnounceRequest {
        let payload = OnionAnnounceRequestPayload {
            ping_id: ping_id.unwrap_or_else(initial_ping_id),
            search_pk: self.search_pk,
            data_pk: self.data_pk.unwrap_or(PublicKey([0; 32])),
            sendback_data: request_id,
        };
        InnerOnionAnnounceRequest::new(
            &precompute(node_pk, self.packet_sk),
            &self.packet_pk,
            &payload
        )
    }
}

/// Onion client state.
#[derive(Clone, Debug)]
struct OnionClientState {
    /// Pool of random onion paths.
    paths_pool: PathsPool,
    /// List of nodes we announce ourselves to.
    announce_list: Kbucket<OnionNode>,
    /// Struct that stores and manages requests IDs and timeouts.
    announce_requests: RequestQueue<AnnounceRequestData>,
    /// List of friends we are looking for.
    friends: HashMap<PublicKey, OnionFriend>,
}

impl OnionClientState {
    pub fn new() -> Self {
        OnionClientState {
            paths_pool: PathsPool::new(),
            announce_list: Kbucket::new(MAX_ONION_ANNOUNCE_NODES),
            announce_requests: RequestQueue::new(ANNOUNCE_TIMEOUT),
            friends: HashMap::new(),
        }
    }
}

/// Onion client that is responsible for announcing our DHT `PublicKey` to our
/// friends and looking for their DHT `PublicKey`s.
#[derive(Clone)]
pub struct OnionClient {
    /// DHT server instance.
    dht: DhtServer,
    /// TCP connections instance.
    tcp_connections: TcpConnections,
    /// Sink to send DHT `PublicKey` when it gets known. The first key is a long
    /// term key, the second key is a DHT key.
    dht_pk_tx: DhtPkTx,
    /// Our long term `SecretKey`.
    real_sk: SecretKey,
    /// Our long term `PublicKey`.
    real_pk: PublicKey,
    /// `SecretKey` for data packets that we can accept.
    data_sk: SecretKey,
    /// `PublicKey` that should be used to encrypt data packets that we can
    /// accept.
    data_pk: PublicKey,
    /// Onion client state.
    state: Arc<Mutex<OnionClientState>>,
}

impl OnionClient {
    /// Create new `OnionClient`.
    pub fn new(
        dht: DhtServer,
        tcp_connections: TcpConnections,
        dht_pk_tx: DhtPkTx,
        real_sk: SecretKey,
        real_pk: PublicKey
    ) -> Self {
        let (data_pk, data_sk) = gen_keypair();
        OnionClient {
            dht,
            tcp_connections,
            dht_pk_tx,
            real_sk,
            real_pk,
            data_sk,
            data_pk,
            state: Arc::new(Mutex::new(OnionClientState::new())),
        }
    }

    fn is_redundant_ping(&self, pk: PublicKey, search_pk: PublicKey, request_queue: &RequestQueue<AnnounceRequestData>) -> bool {
        let check_pks = |data: &AnnounceRequestData| -> bool {
            let request_search_pk = if let Some(friend_pk) = data.friend_pk {
                friend_pk
            } else {
                self.dht.pk
            };
            data.pk == pk && search_pk == request_search_pk
        };
        request_queue.get_values()
            .any(|(ping_time, request_data)| check_pks(request_data) &&
                clock_elapsed(ping_time) < Duration::from_secs(MIN_NODE_PING_TIME))
    }

    /// Handle `OnionAnnounceResponse` packet.
    pub fn handle_announce_response(&self, packet: &OnionAnnounceResponse, _addr: SocketAddr) -> impl Future<Item = (), Error = Error> + Send {
        let state = &mut *self.state.lock();

        let announce_data = if let Some(announce_data) = state.announce_requests.check_ping_id(packet.sendback_data, |_| true) {
            announce_data
        } else {
            return Either::A(future::err(Error::new(ErrorKind::Other, "handle_announce_response: invalid request id")))
        };

        // Assign variables depending on response type (was it announcing or searching request)
        let (nodes_list, last_seen, announce_packet_data) = if let Some(ref friend_pk) = announce_data.friend_pk {
            if let Some(friend) = state.friends.get_mut(friend_pk) {
                let announce_packet_data = AnnouncePacketData {
                    packet_sk: &friend.temporary_sk,
                    packet_pk: friend.temporary_pk,
                    search_pk: friend.real_pk,
                    data_pk: None,
                };
                (&mut friend.close_nodes, Some(&mut friend.last_seen), announce_packet_data)
            } else {
                return Either::A(future::err(Error::new(ErrorKind::Other, "handle_announce_response: no friend with such pk")))
            }
        } else {
            let announce_packet_data = AnnouncePacketData {
                packet_sk: &self.real_sk,
                packet_pk: self.real_pk,
                search_pk: self.real_pk,
                data_pk: Some(self.data_pk),
            };
            (&mut state.announce_list, None, announce_packet_data)
        };

        let payload = match packet.get_payload(&precompute(&announce_data.pk, announce_packet_data.packet_sk)) {
            Ok(payload) => payload,
            Err(e) => return Either::A(future::err(Error::new(ErrorKind::Other, e.compat())))
        };

        trace!("OnionAnnounceResponse status: {:?}, data: {:?}", payload.announce_status, announce_data);

        if announce_data.friend_pk.is_some() && payload.announce_status == AnnounceStatus::Announced ||
            announce_data.friend_pk.is_none() && payload.announce_status == AnnounceStatus::Found {
            return Either::A(future::err(Error::new(ErrorKind::Other, "Invalid announce status")));
        }

        state.paths_pool.set_timeouts(announce_data.path_id, announce_data.friend_pk.is_some());

        if payload.announce_status == AnnounceStatus::Found {
            if let Some(last_seen) = last_seen {
                *last_seen = Some(clock_now());
            }
        }

        let (ping_id, data_pk) = if payload.announce_status == AnnounceStatus::Found {
            (None, Some(digest_as_pk(payload.ping_id_or_pk)))
        } else {
            (Some(payload.ping_id_or_pk), None)
        };

        let now = clock_now();
        nodes_list.try_add(&announce_packet_data.search_pk, OnionNode {
            pk: announce_data.pk,
            saddr: announce_data.saddr,
            path_id: announce_data.path_id,
            ping_id,
            data_pk,
            unsuccessful_pings: 0,
            added_time: now,
            ping_time: now,
            response_time: now,
            announce_status: payload.announce_status,
        }, /* evict */ true);

        state.paths_pool.path_nodes.put(PackedNode::new(announce_data.saddr, &announce_data.pk));

        let mut futures = Vec::with_capacity(payload.nodes.len());

        for node in &payload.nodes {
            if !nodes_list.can_add(&announce_packet_data.search_pk, &node, /* evict */ true) {
                continue;
            }

            // To prevent to send redundant ping packet.
            if self.is_redundant_ping(node.pk, announce_packet_data.search_pk, &state.announce_requests) {
                continue;
            }

            let path = if let Some(path) = state.paths_pool.random_path(announce_data.friend_pk.is_some()) {
                path
            } else {
                continue
            };

            let request_id = state.announce_requests.new_ping_id(AnnounceRequestData {
                pk: node.pk,
                saddr: node.saddr,
                path_id: path.id(),
                friend_pk: announce_data.friend_pk,
            });

            let inner_announce_request = announce_packet_data.request(&node.pk, None, request_id);
            let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request));

            futures.push(send_to(&self.dht.tx, (Packet::OnionRequest0(onion_request), path.nodes[0].saddr)));
        }

        Either::B(future::join_all(futures)
            .map(|_| ())
            .map_err(|e| Error::new(ErrorKind::Other, e)))
    }

    /// Handle DHT `PublicKey` announce from both onion and DHT.
    pub fn handle_dht_pk_announce(&self, friend_pk: PublicKey, dht_pk_announce: DhtPkAnnouncePayload) -> impl Future<Item = (), Error = Error> + Send {
        let mut state = self.state.lock();

        let friend = match state.friends.get_mut(&friend_pk) {
            Some(friend) => friend,
            None => return Either::A(future::err(Error::new(ErrorKind::Other, "handle_dht_pk_announce: no friend with such pk")))
        };

        if dht_pk_announce.no_reply <= friend.last_no_reply {
            return Either::A(future::err(Error::new(ErrorKind::Other, "handle_dht_pk_announce: invalid no_reply")))
        }

        friend.last_no_reply = dht_pk_announce.no_reply;
        friend.dht_pk = Some(dht_pk_announce.dht_pk);
        friend.last_seen = Some(clock_now());

        let dht_pk_future = send_to(&self.dht_pk_tx, (friend_pk, dht_pk_announce.dht_pk));

        let futures = dht_pk_announce.nodes.into_iter().map(|node| match node.ip_port.protocol {
            ProtocolType::UDP => {
                let packed_node = PackedNode::new(node.ip_port.to_saddr(), &node.pk);
                Either::A(self.dht.ping_node(&packed_node).map_err(|e| Error::new(ErrorKind::Other, e.compat())))
            },
            ProtocolType::TCP => {
                Either::B(self.tcp_connections.add_relay_connection(node.ip_port.to_saddr(), node.pk, friend_pk))
            }
        }).collect::<Vec<_>>();

        Either::B(dht_pk_future
            .map_err(|e| Error::new(ErrorKind::Other, e))
            .join(future::join_all(futures).map(|_| ()))
            .map(|_| ()))
    }

    /// Handle `OnionDataResponse` packet.
    pub fn handle_data_response(&self, packet: &OnionDataResponse) -> impl Future<Item = (), Error = Error> + Send {
        let payload = match packet.get_payload(&precompute(&packet.temporary_pk, &self.data_sk)) {
            Ok(payload) => payload,
            Err(e) => return Either::A(future::err(Error::new(ErrorKind::Other, e.compat())))
        };
        let iner_payload = match payload.get_payload(&packet.nonce, &precompute(&payload.real_pk, &self.real_sk)) {
            Ok(payload) => payload,
            Err(e) => return Either::A(future::err(Error::new(ErrorKind::Other, e.compat())))
        };
        match iner_payload {
            OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce) => Either::B(self.handle_dht_pk_announce(payload.real_pk, dht_pk_announce)),
            OnionDataResponseInnerPayload::FriendRequest(_) => Either::A(future::ok(()))
        }
    }

    /// Add new node to random nodes pool to use them to build random paths.
    pub fn add_path_node(&self, node: PackedNode) {
        let mut state = self.state.lock();

        state.paths_pool.path_nodes.put(node);
    }

    /// Add new node to random nodes pool to use them to build random paths.
    pub fn add_friend(&self, real_pk: PublicKey) {
        let mut state = self.state.lock();

        state.friends.insert(real_pk, OnionFriend::new(real_pk));
    }

    /// Generic function for sending search and announce requests to close nodes.
    fn ping_close_nodes(
        close_nodes: &mut Kbucket<OnionNode>,
        paths_pool: &mut PathsPool,
        announce_requests: &mut RequestQueue<AnnounceRequestData>,
        announce_packet_data: AnnouncePacketData,
        friend_pk: Option<PublicKey>,
        interval: Option<Duration>
    ) -> Vec<(Packet, SocketAddr)> {
        let capacity = close_nodes.capacity();
        let ping_random = close_nodes.iter().all(|node|
            clock_elapsed(node.ping_time) >= Duration::from_secs(ONION_NODE_PING_INTERVAL) &&
                // ensure we get a response from some node roughly once per interval / capacity
                interval.map_or(true, |interval| clock_elapsed(node.response_time) >= interval / capacity as u32)
        );
        let mut packets = Vec::new();
        let mut good_nodes_count = 0;
        for node in close_nodes.iter_mut() {
            if !node.is_timed_out() {
                good_nodes_count += 1;
            }

            if node.is_ping_attempts_exhausted() {
                continue;
            }

            let interval = if let Some(interval) = interval {
                interval
            } else if node.announce_status == AnnounceStatus::Announced {
                if let Some(stored_path) = paths_pool.get_stored_path(node.path_id, friend_pk.is_some()) {
                    if node.is_stable() && stored_path.is_stable() {
                        Duration::from_secs(ANNOUNCE_INTERVAL_STABLE)
                    } else {
                        Duration::from_secs(ANNOUNCE_INTERVAL_ANNOUNCED)
                    }
                } else {
                    Duration::from_secs(ANNOUNCE_INTERVAL_NOT_ANNOUNCED)
                }
            } else {
                Duration::from_secs(ANNOUNCE_INTERVAL_NOT_ANNOUNCED)
            };

            if clock_elapsed(node.ping_time) >= interval || ping_random && random_limit_usize(capacity) == 0 {
                // Last chance for a long-lived node
                let path = if node.is_last_ping_attempt() && node.is_stable() {
                    paths_pool.random_path(friend_pk.is_some())
                } else {
                    paths_pool.use_path(node.path_id, friend_pk.is_some())
                };

                let path = if let Some(path) = path {
                    path
                } else {
                    continue
                };

                node.unsuccessful_pings += 1;
                node.ping_time = clock_now();

                let request_id = announce_requests.new_ping_id(AnnounceRequestData {
                    pk: node.pk,
                    saddr: node.saddr,
                    path_id: path.id(),
                    friend_pk,
                });

                let inner_announce_request = announce_packet_data.request(&node.pk, node.ping_id, request_id);
                let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request));

                packets.push((Packet::OnionRequest0(onion_request), path.nodes[0].saddr));
            }
        }

        if good_nodes_count <= random_limit_usize(close_nodes.capacity()) {
            for _ in 0 .. close_nodes.capacity() / 2 {
                let node = if let Some(node) = paths_pool.path_nodes.rand() {
                    node
                } else {
                    break
                };

                let path = if let Some(path) = paths_pool.random_path(friend_pk.is_some()) {
                    path
                } else {
                    break
                };

                let request_id = announce_requests.new_ping_id(AnnounceRequestData {
                    pk: node.pk,
                    saddr: node.saddr,
                    path_id: path.id(),
                    friend_pk,
                });

                let inner_announce_request = announce_packet_data.request(&node.pk, None, request_id);
                let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionAnnounceRequest(inner_announce_request));

                packets.push((Packet::OnionRequest0(onion_request), path.nodes[0].saddr));
            }
        }

        packets
    }

    /// Announce ourselves periodically.
    fn announce_loop(&self, state: &mut OnionClientState) -> impl Future<Item = (), Error = Error> + Send {
        let announce_packet_data = AnnouncePacketData {
            packet_sk: &self.real_sk,
            packet_pk: self.real_pk,
            search_pk: self.real_pk,
            data_pk: Some(self.data_pk),
        };

        let packets = OnionClient::ping_close_nodes(
            &mut state.announce_list,
            &mut state.paths_pool,
            &mut state.announce_requests,
            announce_packet_data,
            None,
            None,
        );

        send_all_to(&self.dht.tx, stream::iter_ok(packets))
            .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
    }

    /// Get nodes to include to DHT `PublicKey` announcement packet.
    fn dht_pk_nodes(&self) -> Vec<TcpUdpPackedNode> {
        let relays = self.tcp_connections.get_random_relays(2);
        let close_nodes: Vec<PackedNode> = self.dht.get_closest(&self.dht.pk, 4 - relays.len() as u8, true).into();
        relays.into_iter().map(|node| TcpUdpPackedNode {
            pk: node.pk,
            ip_port: IpPort::from_tcp_saddr(node.saddr),
        }).chain(close_nodes.into_iter().map(|node| TcpUdpPackedNode {
            pk: node.pk,
            ip_port: IpPort::from_udp_saddr(node.saddr),
        })).collect()
    }

    /// Announce our DHT `PublicKey` to a friend via onion.
    fn send_dht_pk_onion(&self, friend: &mut OnionFriend, paths_pool: &mut PathsPool) -> Vec<(Packet, SocketAddr)> {
        let dht_pk_announce = DhtPkAnnouncePayload::new(self.dht.pk, self.dht_pk_nodes());
        let inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce);
        let nonce = gen_nonce();
        let payload = OnionDataResponsePayload::new(&precompute(&friend.real_pk, &self.real_sk), self.real_pk, &nonce, &inner_payload);

        let mut packets = Vec::new();

        for node in friend.close_nodes.iter() {
            if node.is_timed_out() {
                continue;
            }

            let data_pk = if let Some(data_pk) = node.data_pk {
                data_pk
            } else {
                continue
            };

            let path = if let Some(path) = paths_pool.use_path(node.path_id, true) {
                path
            } else {
                continue
            };

            let (temporary_pk, temporary_sk) = gen_keypair();
            let inner_data_request = InnerOnionDataRequest::new(&precompute(&data_pk, &temporary_sk), friend.real_pk, temporary_pk, nonce, &payload);

            let onion_request = path.create_onion_request(node.saddr, InnerOnionRequest::InnerOnionDataRequest(inner_data_request));

            packets.push((Packet::OnionRequest0(onion_request), path.nodes[0].saddr));
        }

        if !packets.is_empty() {
            friend.last_dht_pk_onion_sent = Some(clock_now());
        }

        packets
    }

    /// Announce our DHT `PublicKey` to a friend via `DhtRequest`.
    fn send_dht_pk_dht_request(&self, friend: &mut OnionFriend) -> Vec<(Packet, SocketAddr)> {
        let friend_dht_pk = if let Some(friend_dht_pk) = friend.dht_pk {
            friend_dht_pk
        } else {
            return Vec::new()
        };

        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(self.dht.pk, self.dht_pk_nodes());
        let dht_pk_announce = DhtPkAnnounce::new(&precompute(&friend.real_pk, &self.real_sk), self.real_pk, &dht_pk_announce_payload);
        let payload = DhtRequestPayload::DhtPkAnnounce(dht_pk_announce);
        let packet = DhtRequest::new(&precompute(&friend_dht_pk, &self.dht.sk), &friend_dht_pk, &self.dht.pk, &payload);
        let packet = Packet::DhtRequest(packet);

        let nodes = self.dht.get_closest(&friend_dht_pk, 8, false);

        if !nodes.is_empty() {
            friend.last_dht_pk_dht_sent = Some(clock_now());
        }

        nodes.iter().map(|node| (packet.clone(), node.saddr)).collect()
    }

    /// Search friends periodically.
    fn friends_loop(&self, state: &mut OnionClientState) -> impl Future<Item = (), Error = Error> + Send {
        let mut packets = Vec::new();

        for friend in state.friends.values_mut() {
            // TODO: if is_online

            let announce_packet_data = AnnouncePacketData {
                packet_sk: &friend.temporary_sk,
                packet_pk: friend.temporary_pk,
                search_pk: friend.real_pk,
                data_pk: None,
            };

            let interval = if friend.search_count < SEARCH_COUNT_FRIEND_ANNOUNCE_BEGINNING {
                Duration::from_secs(ANNOUNCE_FRIEND_BEGINNING)
            } else {
                let backoff_interval = friend.last_seen.map_or_else(
                    || Duration::from_secs(ONION_FRIEND_MAX_PING_INTERVAL),
                    |last_seen| clock_elapsed(last_seen) / ONION_FRIEND_BACKOFF_FACTOR
                );
                backoff_interval
                    .min(Duration::from_secs(ONION_FRIEND_MAX_PING_INTERVAL))
                    .max(Duration::from_secs(ANNOUNCE_FRIEND))
            };

            let friend_packets = OnionClient::ping_close_nodes(
                &mut friend.close_nodes,
                &mut state.paths_pool,
                &mut state.announce_requests,
                announce_packet_data,
                Some(friend.real_pk),
                Some(interval),
            );

            if !friend_packets.is_empty() {
                friend.search_count = friend.search_count.saturating_add(1);
            }

            packets.extend(friend_packets);

            if friend.last_dht_pk_onion_sent.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(ONION_DHTPK_SEND_INTERVAL)) {
                packets.extend(self.send_dht_pk_onion(friend, &mut state.paths_pool));
            }

            if friend.last_dht_pk_dht_sent.map_or(true, |time| clock_elapsed(time) > Duration::from_secs(DHT_DHTPK_SEND_INTERVAL)) {
                packets.extend(self.send_dht_pk_dht_request(friend));
            }
        }

        send_all_to(&self.dht.tx, stream::iter_ok(packets))
            .map_err(|e| Error::new(ErrorKind::Other, e.compat()))
    }

    /// Populate nodes pool from DHT for building random paths.
    fn populate_path_nodes(&self, state: &mut OnionClientState) {
        for node in self.dht.random_friend_nodes(MAX_ONION_FRIEND_NODES) {
            state.paths_pool.path_nodes.put(node);
        }
    }

    /// Run periodical announcements and friends searching.
    pub fn run(self) -> impl Future<Item = (), Error = Error> + Send {
        let interval = Duration::from_secs(1);
        let wakeups = Interval::new(Instant::now(), interval);
        wakeups
            .map_err(|e| Error::new(ErrorKind::Other, e))
            .for_each(move |_instant| {
                trace!("Onion client sender wake up");
                let mut state = self.state.lock();
                self.populate_path_nodes(&mut state);
                let announce_future = self.announce_loop(&mut state);
                let friends_future = self.friends_loop(&mut state);
                announce_future.join(friends_future).map(|_| ())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_announce_response_announced() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, dht_pk_tx, real_sk, real_pk);

        let mut state = onion_client.state.lock();

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.random_path(false).unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        // the sender will be added to the nodes pool so add it to the map
        key_by_addr.insert(saddr, sender_sk.clone());

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: None,
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let ping_id = sha256::hash(&[1, 2, 3]);
        let (node_pk, node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Announced,
            ping_id_or_pk: ping_id,
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&real_pk, &sender_sk), request_id, &payload);

        onion_client.handle_announce_response(&packet, saddr).wait().unwrap();

        let state = onion_client.state.lock();

        // The sender should be added to close nodes
        let onion_node = state.announce_list.get_node(&real_pk, &sender_pk).unwrap();
        assert_eq!(onion_node.path_id, path.id());
        assert_eq!(onion_node.ping_id, Some(ping_id));
        assert_eq!(onion_node.data_pk, None);
        assert_eq!(onion_node.announce_status, AnnounceStatus::Announced);

        // Node from the packet should be pinged
        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        let packet = unpack!(packet, Packet::OnionRequest0);
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&addr_to_send])).unwrap();
        let packet = OnionRequest1 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 123],
            }
        };
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
        let packet = OnionRequest2 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 123],
            }
        };
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
        let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
        let payload = packet.get_payload(&precompute(&real_pk, &node_sk)).unwrap();
        assert_eq!(payload.ping_id, initial_ping_id());
        assert_eq!(payload.search_pk, real_pk);
        assert_eq!(payload.data_pk, onion_client.data_pk);
    }

    #[test]
    fn handle_announce_response_announced_invalid_status() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, dht_pk_tx, real_sk, real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;
        state.friends.insert(friend_pk, friend);

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.random_path(false).unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let ping_id = sha256::hash(&[1, 2, 3]);
        let (node_pk, _node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Announced,
            ping_id_or_pk: ping_id,
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&friend_temporary_pk, &sender_sk), request_id, &payload);

        assert!(onion_client.handle_announce_response(&packet, saddr).wait().is_err());
    }

    #[test]
    fn handle_announce_response_found() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, dht_pk_tx, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let (friend_pk, _friend_sk) = gen_keypair();
        let friend = OnionFriend::new(friend_pk);
        let friend_temporary_pk = friend.temporary_pk;
        state.friends.insert(friend_pk, friend);

        // map needed to decrypt onion packets later
        let mut key_by_addr = HashMap::new();
        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, sk) = gen_keypair();
            key_by_addr.insert(saddr, sk);
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.random_path(false).unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        // the sender will be added to the nodes pool so add it to the map
        key_by_addr.insert(saddr, sender_sk.clone());

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: Some(friend_pk),
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let (friend_data_pk, _friend_data_sk) = gen_keypair();
        let (node_pk, node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: pk_as_digest(friend_data_pk),
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&friend_temporary_pk, &sender_sk), request_id, &payload);

        onion_client.handle_announce_response(&packet, saddr).wait().unwrap();

        let state = onion_client.state.lock();

        // The sender should be added to close nodes
        let onion_node = state.friends[&friend_pk].close_nodes.get_node(&real_pk, &sender_pk).unwrap();
        assert_eq!(onion_node.path_id, path.id());
        assert_eq!(onion_node.ping_id, None);
        assert_eq!(onion_node.data_pk, Some(friend_data_pk));
        assert_eq!(onion_node.announce_status, AnnounceStatus::Found);

        // Node from the packet should be pinged
        let (received, _udp_rx) = udp_rx.into_future().wait().unwrap();
        let (packet, addr_to_send) = received.unwrap();

        let packet = unpack!(packet, Packet::OnionRequest0);
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&addr_to_send])).unwrap();
        let packet = OnionRequest1 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 123],
            }
        };
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
        let packet = OnionRequest2 {
            nonce: packet.nonce,
            temporary_pk: payload.temporary_pk,
            payload: payload.inner,
            onion_return: OnionReturn {
                nonce: secretbox::gen_nonce(),
                payload: vec![42; 123],
            }
        };
        let payload = packet.get_payload(&precompute(&packet.temporary_pk, &key_by_addr[&payload.ip_port.to_saddr()])).unwrap();
        let packet = unpack!(payload.inner, InnerOnionRequest::InnerOnionAnnounceRequest);
        let payload = packet.get_payload(&precompute(&friend_temporary_pk, &node_sk)).unwrap();
        assert_eq!(payload.ping_id, initial_ping_id());
        assert_eq!(payload.search_pk, friend_pk);
        assert_eq!(payload.data_pk, PublicKey([0; 32]));
    }

    #[test]
    fn handle_announce_response_found_invalid_status() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, _dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, dht_pk_tx, real_sk.clone(), real_pk);

        let mut state = onion_client.state.lock();

        let addr = "127.0.0.1".parse().unwrap();
        for i in 0 .. 3 {
            let saddr = SocketAddr::new(addr, 12346 + i);
            let (pk, _sk) = gen_keypair();
            let node = PackedNode::new(saddr, &pk);
            state.paths_pool.path_nodes.put(node);
        }
        let path = state.paths_pool.random_path(false).unwrap();

        let (sender_pk, sender_sk) = gen_keypair();
        let saddr = "127.0.0.1:12345".parse().unwrap();

        let request_data = AnnounceRequestData {
            pk: sender_pk,
            saddr,
            path_id: path.id(),
            friend_pk: None,
        };
        let request_id = state.announce_requests.new_ping_id(request_data);

        drop(state);

        let (friend_data_pk, _friend_data_sk) = gen_keypair();
        let (node_pk, _node_sk) = gen_keypair();
        let node = PackedNode::new(SocketAddr::V4("5.6.7.8:12345".parse().unwrap()), &node_pk);
        let payload = OnionAnnounceResponsePayload {
            announce_status: AnnounceStatus::Found,
            ping_id_or_pk: pk_as_digest(friend_data_pk),
            nodes: vec![node]
        };
        let packet = OnionAnnounceResponse::new(&precompute(&real_pk, &sender_sk), request_id, &payload);

        assert!(onion_client.handle_announce_response(&packet, saddr).wait().is_err());
    }

    #[test]
    fn handle_data_response_dht_pk_announce() {
        crypto_init().unwrap();
        let (dht_pk, dht_sk) = gen_keypair();
        let (real_pk, real_sk) = gen_keypair();
        let (udp_tx, _udp_rx) = mpsc::channel(1);
        let (tcp_incoming_tx, _tcp_incoming_rx) = mpsc::unbounded();
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        let dht = DhtServer::new(udp_tx, dht_pk, dht_sk.clone());
        let tcp_connections = TcpConnections::new(dht_pk, dht_sk, tcp_incoming_tx);
        let onion_client = OnionClient::new(dht, tcp_connections, dht_pk_tx, real_sk.clone(), real_pk);

        let (friend_dht_pk, _friend_dht_sk) = gen_keypair();
        let (friend_real_pk, friend_real_sk) = gen_keypair();

        onion_client.add_friend(friend_real_pk);

        let dht_pk_announce_payload = DhtPkAnnouncePayload::new(friend_dht_pk, vec![]);
        let no_reply = dht_pk_announce_payload.no_reply;
        let onion_data_response_inner_payload = OnionDataResponseInnerPayload::DhtPkAnnounce(dht_pk_announce_payload);
        let nonce = gen_nonce();
        let onion_data_response_payload = OnionDataResponsePayload::new(&precompute(&real_pk, &friend_real_sk), friend_real_pk, &nonce, &onion_data_response_inner_payload);
        let (temporary_pk, temporary_sk) = gen_keypair();
        let onion_data_response = OnionDataResponse::new(&precompute(&onion_client.data_pk, &temporary_sk), temporary_pk, nonce, &onion_data_response_payload);

        onion_client.handle_data_response(&onion_data_response).wait().unwrap();

        let state = onion_client.state.lock();

        // friend should have updated data
        let friend = &state.friends[&friend_real_pk];
        assert_eq!(friend.last_no_reply, no_reply);
        assert_eq!(friend.dht_pk, Some(friend_dht_pk));

        // friend's DHT key should be sent to dht_pk_tx
        let (received, _dht_pk_rx) = dht_pk_rx.into_future().wait().unwrap();
        let (received_real_pk, received_dht_pk) = received.unwrap();
        assert_eq!(received_real_pk, friend_real_pk);
        assert_eq!(received_dht_pk, friend_dht_pk);
    }
}
