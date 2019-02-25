/*! The implementation of Friend connection
*/

pub mod packet;

use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;

use futures::{Future, Stream, future};
use futures::sync::mpsc;
use parking_lot::RwLock;

use crate::toxcore::crypto_core::*;
use crate::toxcore::dht::server::{Server as DhtServer};
use crate::toxcore::net_crypto::NetCrypto;
use crate::toxcore::onion::client::OnionClient;
use crate::toxcore::tcp::client::{Connections as TcpConnections};

#[derive(Clone)]
pub struct FriendConnections {
    real_sk: SecretKey,
    real_pk: PublicKey,
    friends: Arc<RwLock<HashMap<PublicKey, Option<PublicKey>>>>,
    dht: DhtServer,
    tcp_connections: TcpConnections,
    onion_client: OnionClient,
    net_crypto: NetCrypto,
}

impl FriendConnections {
    pub fn new(
        real_sk: SecretKey,
        real_pk: PublicKey,
        dht: DhtServer,
        tcp_connections: TcpConnections,
        onion_client: OnionClient,
        net_crypto: NetCrypto,
    ) -> Self {
        FriendConnections {
            real_sk,
            real_pk,
            friends: Arc::new(RwLock::new(HashMap::new())),
            dht,
            tcp_connections,
            onion_client,
            net_crypto,
        }
    }

    pub fn add_friend(&self, friend_pk: PublicKey) {
        self.friends.write().insert(friend_pk, None);
        self.onion_client.add_friend(friend_pk);
        self.net_crypto.add_friend(friend_pk);
    }

    pub fn run(self) -> impl Future<Item = (), Error = Error> + Send {
        let (dht_pk_tx, dht_pk_rx) = mpsc::unbounded();
        self.onion_client.set_dht_pk_sink(dht_pk_tx.clone());
        self.net_crypto.set_dht_pk_sink(dht_pk_tx);

        let (friend_saddr_tx, friend_saddr_rx) = mpsc::unbounded();
        self.dht.set_friend_saddr_sink(friend_saddr_tx);

        let (onion_announce_response_tx, onion_announce_response_rx) = mpsc::unbounded();
        self.dht.set_onion_announce_response_sink(onion_announce_response_tx);

        let (onion_data_response_tx, onion_data_response_rx) = mpsc::unbounded();
        self.dht.set_onion_data_response_sink(onion_data_response_tx);

        let dht_c = self.dht.clone();
        // let net_crypto_c = self.net_crypto.clone();
        let friends_c = self.friends.clone();
        let dht_pk_future = dht_pk_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |(real_pk, dht_pk)| {
                info!("Found a friend's DHT key");
                if let Some(friend) = friends_c.write().get_mut(&real_pk) {
                    *friend = Some(dht_pk);
                }
                dht_c.add_friend(dht_pk);
                // net_crypto_c.add_connection(real_pk, dht_pk);
                future::ok(())
            });

        let net_crypto_c = self.net_crypto.clone();
        let friends_c = self.friends.clone();
        let friend_saddr_future = friend_saddr_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |node| {
                info!("Found a friend's IP address");
                if let Some(real_pk) = friends_c.read().iter().find(|t| *t.1 == Some(node.pk)).map(|t| *t.0) {
                    net_crypto_c.add_connection(real_pk, node.pk);

                    net_crypto_c.set_friend_udp_addr(real_pk, node.saddr);
                }
                future::ok(())
            });

        let onion_client_c = self.onion_client.clone();
        let announce_response_future = onion_announce_response_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |(packet, saddr)|
                onion_client_c.handle_announce_response(&packet, saddr).then(|_| Ok(()))
            );

        let onion_client_c = self.onion_client.clone();
        let data_response_future = onion_data_response_rx
            .map_err(|()| -> Error { unreachable!("rx can't fail") })
            .for_each(move |(packet, _saddr)|
                onion_client_c.handle_data_response(&packet).then(|_| Ok(()))
            );

        future::select_all(vec![
            Box::new(dht_pk_future) as Box<Future<Item = (), Error = Error> + Send>,
            Box::new(friend_saddr_future),
            Box::new(announce_response_future),
            Box::new(data_response_future),
        ]).map(|_| ()).map_err(|(e, _, _)| e)
    }
}
