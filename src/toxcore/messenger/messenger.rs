/*! The temporary friends and messenger module for waiting completion of friends module.
*/

use std::collections::HashMap;
use std::sync::Arc;
use std::ops::{Add, Sub};

use futures::{future, Future};
use futures::future::Either;
use futures::sync::mpsc::*;
use parking_lot::RwLock;
use bitflags::*;

use crate::toxcore::binary_io::*;
use crate::toxcore::crypto_core::*;
use crate::toxcore::net_crypto::*;
use crate::toxcore::state_format::old::*;
use crate::toxcore::messenger::packet::*;
use crate::toxcore::io_tokio::*;
use crate::toxcore::dht::packet::*;
use crate::toxcore::messenger::errors::*;
use crate::toxcore::messenger::packet::Packet as MsgPacket;
use crate::toxcore::onion::client::*;

/// Because `file_id` is `u8` this const can not be larger than 256.
pub const MAX_CONCURRENT_FILE_PIPES: u32 = 256;

/// File transferring status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    /// Not accepted
    NotAccepted,
    /// Transferring
    Transferring,
    /// Finished
    Finished,
}

bitflags! {
    /// File transferring pause status
    pub struct PauseStatus: u8 {
        /// Not paused
        const FT_NONE = 0;
        /// Paused by us
        const US = 1;
        /// Paused by other
        const OTHER = 2;
        /// Paused by both
        const BOTH = 3;
    }
}

/** File sending

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTransfers {
    /// Size in bytes of a file to transfer.
    pub size: u64,
    /// Size in bytes of a file already transferred.
    pub transferred: u64,
    /// Status of transferring
    pub status: TransferStatus,
    /// Status of pausing
    pub pause: PauseStatus,
    /// Number of last packet sent.
    pub last_packet_number: u32,
    /// Data requested by the request chunk callback.
    pub requested: u64,
    /// Unique file id for this transfer
    pub unique_id: FileUID,
}

impl FileTransfers {
    /// Make new FileTransfers object
    pub fn new() -> Self {
        FileTransfers {
            size: 0,
            transferred: 0,
            status: TransferStatus::NotAccepted,
            pause: PauseStatus::FT_NONE,
            last_packet_number: 0,
            requested: 0,
            unique_id: FileUID::new(),
        }
    }
}

/// Messenger object
#[derive(Clone)]
pub struct Messenger {
    /// List of friends
    friends_list: Arc<RwLock<HashMap<PublicKey, OnionFriend>>>,
    /// NetCrypto object
    net_crypto: Option<NetCrypto>,
    /// Sink for file control packets
    recv_file_control_tx: Option<UnboundedSender<(PublicKey, MsgPacket)>>,
    /// Sink for file data packts, `u64` is for file position.
    recv_file_data_tx: Option<Sender<(PublicKey, MsgPacket, u64)>>,
}

impl Messenger {
    /// Create new messenger object
    pub fn new() -> Self {
        Messenger {
            friends_list: Arc::new(RwLock::new(HashMap::new())),
            net_crypto: None,
            recv_file_control_tx: None,
            recv_file_data_tx: None,
        }
    }

    /// Add friend.
    pub fn add_friend(&self, pk: PublicKey, friend: OnionFriend) {
        self.friends_list.write().insert(pk, friend);
    }

    /// Set net_crypto object.
    pub fn set_net_crypto(&mut self, net_cryto: NetCrypto) {
        self.net_crypto = Some(net_cryto);
    }

    /// Set tx for receiver's file control packet.
    pub fn set_tx_file_control(&mut self, tx: UnboundedSender<(PublicKey, MsgPacket)>) {
        self.recv_file_control_tx = Some(tx);
    }

    /// Set tx for receiver's file data pacekt.
    pub fn set_tx_file_data(&mut self, tx: Sender<(PublicKey, MsgPacket, u64)>) {
        self.recv_file_data_tx = Some(tx);
    }

    /// Send file control request.
    fn send_file_control_packet(&self, pk: PublicKey, dir: TransferDirection, file_id: u8, control: ControlType)
                                -> impl Future<Item=(), Error=SendPacketError> + Send {
        if let Some(net_crypto) = &self.net_crypto {
            let packet = FileControl::new(dir, file_id, control);
            let mut buf = [0; MAX_CRYPTO_DATA_SIZE];
            match packet.to_bytes((&mut buf, 0)) {
                Ok((data, size)) => {
                    println!("send file control packet {:?}", data[..size].to_vec().clone());
                    Either::A(net_crypto.send_lossless(pk, data[..size].to_vec())
                        .map_err(|e| SendPacketError::from(e)))
                },
                Err(e) => {
                    println!("send control packet error {:?}", e);
                    Either::B(future::err(SendPacketError::serialize(e)))
                },
            }
        } else {
            println!("No net_crypto in messenger");
            Either::B(future::err(SendPacketErrorKind::NoNetCrypto.into()))
        }
    }

    /// Issue seek file control request
    pub fn send_file_seek(&self, friend_pk: PublicKey, file_id: u8, position: u64) -> impl Future<Item=(), Error=SendPacketError> + Send {
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            if friend.status != FriendStatus::Online {
                return Either::A(future::err(SendPacketErrorKind::NotOnline.into()))
            }

            let file_receive = friend.files_receiving.clone();
            let ft = file_receive.read();
            if let Some(ft) = ft.get(file_id as usize) {
                if let Some(ft) = ft {
                    if ft.status != TransferStatus::NotAccepted {
                        return Either::A(future::err(SendPacketErrorKind::NotAccepted.into()))
                    }
                    if position >= ft.size {
                        return Either::A(future::err(SendPacketErrorKind::LargerPosition.into()))
                    }
                    let mut ft_c = ft.clone();
                    let file_receive_c = file_receive.clone();
                    let future = self.send_file_control_packet(friend.real_pk, TransferDirection::Receive, file_id, ControlType::Seek(position))
                        .and_then(move |_| {
                            ft_c.transferred = position;
                            file_receive_c.write()[file_id as usize] = Some(ft_c);
                            future::ok(())
                        });
                    Either::B(future)
                } else {
                    Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
                }
            } else {
                Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::A(future::err(SendPacketErrorKind::NoFriend.into()))
        }
    }

    /// Issue file control request.
    pub fn send_file_control(&self, friend_pk: PublicKey, file_id: u8, dir: TransferDirection, control: ControlType)
                             -> impl Future<Item=(), Error=SendPacketError> + Send {
        let friend_list = self.friends_list.clone();
        let friend_read = friend_list.read();
        if let Some(friend) = friend_read.get(&friend_pk) {
            if friend.status != FriendStatus::Online {
                return Either::A(future::err(SendPacketErrorKind::NotOnline.into()))
            }

            let files = if dir == TransferDirection::Send {
                friend.files_sending.clone()
            } else {
                friend.files_receiving.clone()
            };

            let ft = files.read();
            if let Some(ft) = ft.get(file_id as usize) {
                if let Some(ft) = ft {
                    if control == ControlType::Pause && (ft.pause & PauseStatus::US == PauseStatus::US || ft.status != TransferStatus::Transferring) {
                        println!("1");
                        return Either::A(future::err(SendPacketErrorKind::InvalidRequest.into()))
                    }

                    if control == ControlType::Accept {
                        if ft.status == TransferStatus::Transferring {
                            if !(ft.pause & PauseStatus::US == PauseStatus::US) {
                                if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                                    println!("2");
                                    return Either::A(future::err(SendPacketErrorKind::InvalidRequest2.into()))
                                }
                                println!("3");
                                return Either::A(future::err(SendPacketErrorKind::InvalidRequest3.into()))
                            }
                        } else {
                            if ft.status != TransferStatus::NotAccepted {
                                println!("4");
                                return Either::A(future::err(SendPacketErrorKind::InvalidRequest4.into()))
                            }
                            if dir == TransferDirection::Send {
                                println!("5");
                                return Either::A(future::err(SendPacketErrorKind::InvalidRequest5.into()))
                            }
                        }
                    }

                    let friend_list_c = friend_list.clone();
                    let files_c = files.clone();
                    let mut ft_c = ft.clone();

                    let future = self.send_file_control_packet(friend.real_pk, dir, file_id, control)
                        .and_then(move |_| {
                            let mut friend_list_c = friend_list_c.write();
                            let friend = friend_list_c.get_mut(&friend_pk).unwrap();
                            if control == ControlType::Kill {
                                if dir == TransferDirection::Send {
                                    friend.num_sending_files = friend.num_sending_files.sub(1);
                                    friend.files_sending.write()[file_id as usize] = None;
                                } else {
                                    friend.files_receiving.write()[file_id as usize] = None;
                                }
                            } else if control == ControlType::Pause {
                                ft_c.pause = ft_c.pause | PauseStatus::US;
                                files_c.write()[file_id as usize] = Some(ft_c);
                            } else if control == ControlType::Accept {
                                ft_c.status = TransferStatus::Transferring;
                                files_c.write()[file_id as usize] = Some(ft_c.clone());
                                if ft_c.pause & PauseStatus::US == PauseStatus::US {
                                    ft_c.pause = ft_c.pause ^ PauseStatus::US;
                                    files_c.write()[file_id as usize] = Some(ft_c);
                                }
                            }
                            println!("Good");
                            future::ok(())
                        });
                    Either::B(future)
                } else {
                    Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
                }
            } else {
                Either::A(future::err(SendPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::A(future::err(SendPacketErrorKind::NoFriend.into()))
        }
    }

    fn recv_from(&self, friend_pk: PublicKey, packet: MsgPacket) -> impl Future<Item=(), Error=RecvPacketError> + Send {
        if let Some(tx) = self.recv_file_control_tx.clone() {
            Either::A(send_to(&tx, (friend_pk, packet))
                .map_err(|e| RecvPacketError::from(e)))
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoSink.into()))
        }
    }

    fn recv_from_data(&self, friend_pk: PublicKey, packet: MsgPacket, position: u64) -> impl Future<Item=(), Error=RecvPacketError> + Send {
        if let Some(tx) = self.recv_file_data_tx.clone() {
            Either::A(send_to(&tx, (friend_pk, packet, position))
                .map_err(|e| RecvPacketError::from(e)))
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoDataSink.into()))
        }
    }

    fn send_req_kill(&self, friend_pk: PublicKey, file_id: u8, transfer_direction: TransferDirection, control_type: ControlType)
                     -> impl Future<Item=(), Error=RecvPacketError> + Send {
        self.send_file_control_packet(friend_pk, transfer_direction, file_id, control_type)
            .map_err(|e| RecvPacketError::from(e))
    }

    /// Handle file control request packet
    pub fn handle_file_control(&self, friend_pk: PublicKey, packet: FileControl)
                           -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let mut friend = self.friends_list.write();
        let friend = friend.get_mut(&friend_pk);
        if let Some(friend) = friend {
            let mut ft_write = if packet.transfer_direction == TransferDirection::Send {
                friend.files_sending.write()
            } else {
                friend.files_receiving.write()
            };

            if let Some(ft) = ft_write.get_mut(packet.file_id as usize) {
                let future = if let Some(ft) = ft {
                    let up_packet = MsgPacket::FileControl(packet.clone());

                    if packet.control_type == ControlType::Accept {
                        if packet.transfer_direction == TransferDirection::Receive && ft.status == TransferStatus::NotAccepted {
                            ft.status = TransferStatus::Transferring;
                        } else {
                            if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                                ft.pause = ft.pause ^ PauseStatus::OTHER;
                            } else {
                                warn!("file control (friend {:?}, file {}): friend told us to resume file transfer that wasn't paused", friend_pk, packet.file_id);
                                return Either::B(future::err(RecvPacketError::invalid_request(friend_pk, packet.file_id)))
                            }
                        }
                    } else if packet.control_type == ControlType::Pause {
                        if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER || ft.status != TransferStatus::Transferring {
                            warn!("file control (friend {:?}, file {}): friend told us to pause file transfer that is already paused", friend_pk, packet.file_id);
                            return Either::B(future::err(RecvPacketError::invalid_request(friend_pk, packet.file_id)))
                        }

                        ft.pause = ft.pause | PauseStatus::OTHER;
                    } else if packet.control_type == ControlType::Kill {
                        if packet.transfer_direction == TransferDirection::Receive {
                            friend.num_sending_files = friend.num_sending_files.sub(1);
                            ft_write[packet.file_id as usize] = None;
                        } else {
                            ft_write[packet.file_id as usize] = None;
                        }
                    } else if let ControlType::Seek(position) = packet.control_type {
                        if ft.status != TransferStatus::NotAccepted || packet.transfer_direction == TransferDirection::Send {
                            warn!("file control (friend {:?}, file {}): seek was either sent by a sender or by the receiver after accepting", friend_pk, packet.file_id);
                            return Either::B(future::err(RecvPacketError::invalid_request(friend_pk, packet.file_id)))
                        }
                        if position >= ft.size {
                            warn!("file control (friend {:?}, file {}): seek position {} exceeds file size {}", friend_pk, packet.file_id, position, ft.size);
                            return Either::B(future::err(RecvPacketError::exceed_size(friend_pk, packet.file_id, ft.size)))
                        }
                        ft.requested = position;
                        ft.transferred = position;
                    } else { // unknown file control
                        return Either::B(future::err(RecvPacketErrorKind::UnknownControlType.into()))
                    }

                    Either::A(self.recv_from(friend.real_pk, up_packet))
                } else { // File transfer don't exist; telling the other to kill it
                    warn!("file control (friend {:?}, file {}): file transfer does not exist; telling the other to kill it", friend_pk, packet.file_id);
                    Either::B(self.send_req_kill(friend_pk, packet.file_id, packet.transfer_direction.toggle(), ControlType::Kill))
                };
                Either::A(future)
            } else {
                Either::B(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoFriend.into()))
        }
    }

    /// Handle file send request packet
    pub fn handle_file_send_request(&self, friend_pk: PublicKey, packet: FileSendRequest)
                                -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            let mut ft_write = friend.files_receiving.write();
            if let Some(ft) = ft_write.get(packet.file_id as usize) {
                if let Some(_ft) = ft {
                    Either::B(future::err(RecvPacketErrorKind::AlreadyExist.into()))
                } else {
                    let mut ft = FileTransfers::new();

                    ft.status = TransferStatus::NotAccepted;
                    ft.size = packet.file_size;
                    ft.transferred = 0;
                    ft.pause = PauseStatus::FT_NONE;

                    ft_write[packet.file_id as usize] = Some(ft);

                    Either::A(self.recv_from(friend.real_pk, MsgPacket::FileSendRequest(packet)))
                }
            } else {
                Either::B(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::B(future::err(RecvPacketErrorKind::NoFriend.into()))
        }
    }

    /// Handle file data packet
    pub fn handle_file_data(&self, friend_pk: PublicKey, packet: FileData)
                        -> impl Future<Item=(), Error=RecvPacketError> + Send {
        let mut packet = packet;
        let friend = self.friends_list.read();
        if let Some(friend) = friend.get(&friend_pk) {
            let mut ft_write = friend.files_receiving.write();
            if let Some(ft) = ft_write.get_mut(packet.file_id as usize) {
                if let Some(ft) = ft {
                    if ft.status != TransferStatus::Transferring {
                        return Either::A(future::err(RecvPacketErrorKind::NotTransferring.into()))
                    }

                    let mut data_len = packet.data.len() as u64;
                    let position = ft.transferred;

                    // Prevent more data than the filesize from being passed to clients.
                    if ft.transferred + data_len > ft.size {
                        data_len = ft.size - ft.transferred;
                        packet.data.drain(..data_len as usize);
                    }

                    ft.transferred = ft.transferred.add(data_len);

                    let mut futures = Vec::new();
                    let up_packet = MsgPacket::FileData(packet.clone());

                    futures.push(self.recv_from_data(friend.real_pk, up_packet, position));

                    if data_len > 0 && (ft.transferred >= ft.size || data_len != MAX_FILE_DATA_SIZE as u64) {
                        let packet = MsgPacket::FileData(FileData::new(packet.file_id, Vec::new()));
                        futures.push(self.recv_from_data(friend.real_pk, packet, position));
                    }

                    if data_len == 0 {
                        ft_write[packet.file_id as usize] = None;
                    }

                    Either::B(future::join_all(futures).map(|_| ()))
                } else {
                    Either::A(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
                }
            } else {
                Either::A(future::err(RecvPacketErrorKind::NoFileTransfer.into()))
            }
        } else {
            Either::A(future::err(RecvPacketErrorKind::NoFriend.into()))
        }
    }
}
