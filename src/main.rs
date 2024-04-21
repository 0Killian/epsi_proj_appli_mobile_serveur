mod auth;
mod proto;

use anyhow::Result;
use bluer::{
    adv::Advertisement,
    gatt::local::{
        Application, Characteristic, CharacteristicRead, CharacteristicWrite,
        CharacteristicWriteMethod, ReqError, Service,
    },
    Address,
};

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::RwLock,
};

use futures::FutureExt;

use crate::proto::{Packet, PacketData};

const SERVICE_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x0A8061765C2B4BDDB288F38A94D1F957);
const CHARACTERISTIC_UUID: bluer::Uuid = bluer::Uuid::from_u128(0x37450687DD654C739793950AC81AC824);
const MANUFACTURER_ID: u16 = 0xFFFF;

struct State {
    sessions: RwLock<HashMap<u64, RwLock<Session>>>,
    devices: RwLock<HashMap<Address, u64>>,
}

#[derive(Clone)]
enum Session {
    Login {
        sess_challenge: u32,
        login_failed: bool,
    },
    LoggedIn {
        username: String,
        just_logged_in: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to the bluetooth daemon
    let session = bluer::Session::new().await?;

    // Get the default adapter
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    // Advertise the adapter
    println!(
        "Advertising on Bluetooth adapter {} with address {}",
        adapter.name(),
        adapter.address().await?
    );

    let mut manufacturer_data = BTreeMap::new();
    manufacturer_data.insert(MANUFACTURER_ID, vec![0x01, 0x02, 0x03, 0x04]);
    let le_advertisement = Advertisement {
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        manufacturer_data,
        discoverable: Some(true),
        local_name: Some("Example Server".to_string()),
        ..Default::default()
    };
    let _adv_handle = adapter.advertise(le_advertisement).await?;

    println!(
        "Serving GATT service on bluetooth adapter {}",
        adapter.name()
    );

    let state = Arc::new(State {
        sessions: RwLock::new(HashMap::new()),
        devices: RwLock::new(HashMap::new()),
    });
    let state_write = state.clone();
    let state_read = state.clone();

    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: CHARACTERISTIC_UUID,
                write: Some(CharacteristicWrite {
                    write: true,
                    write_without_response: true,
                    method: CharacteristicWriteMethod::Fun(Box::new(move |data, _| {
                        let state = state_write.clone();

                        println!("Write");
                        async move {
                            let mut sessions = state.sessions.write().await;
                            let packet = proto::Packet::read_from(&mut data.as_slice())
                                .await
                                .map_err(|_| ReqError::Failed)?;

                            match packet.data {
                                proto::PacketData::Login {
                                    username,
                                    password,
                                    challenge,
                                    session_id,
                                } => {
                                    println!("Login request: {} {}", username, password);
                                    if let Some(session) = sessions.get_mut(&session_id) {
                                        let mut session = session.write().await;
                                        if let Session::Login { sess_challenge, .. } = *session {
                                            if auth::compute_challenge(sess_challenge) == challenge
                                            {
                                                if username == "username" && password == "password"
                                                {
                                                    println!("Login success");
                                                    *session = Session::LoggedIn {
                                                        username,
                                                        just_logged_in: true,
                                                    };
                                                    Ok(())
                                                } else {
                                                    println!("Login failed");
                                                    *session = Session::Login {
                                                        sess_challenge,
                                                        login_failed: true,
                                                    };
                                                    Ok(())
                                                }
                                            } else {
                                                println!("Wrong challenge");
                                                Err(ReqError::Failed)
                                            }
                                        } else {
                                            println!("Invalid session");
                                            Err(ReqError::Failed)
                                        }
                                    } else {
                                        println!("Invalid session");
                                        Err(ReqError::Failed)
                                    }
                                }
                                _ => Err(ReqError::Failed),
                            }
                        }
                        .boxed()
                    })),
                    ..Default::default()
                }),
                read: Some(CharacteristicRead {
                    read: true,
                    fun: Box::new(move |req| {
                        let state = state_read.clone();
                        println!("Read!");
                        async move {
                            let mut sessions = state.sessions.write().await;
                            let mut devices = state.devices.write().await;
                            if let Some(session_id) = devices.get(&req.device_address) {
                                if let Some(session) = sessions.get(session_id) {
                                    let mut session = session.write().await;
                                    match &(*session) {
                                        Session::LoggedIn {
                                            username,
                                            just_logged_in: true,
                                        } => {
                                            *session = Session::LoggedIn {
                                                username: username.to_string(),
                                                just_logged_in: false,
                                            };
                                            println!("Sending login success packet");
                                            Ok(Vec::<u8>::from(proto::Packet::construct_from(
                                                proto::PacketData::LoginSuccess {},
                                            )))
                                        }
                                        Session::Login {
                                            login_failed: true, ..
                                        } => {
                                            println!("Sending login failure packet");
                                            Ok(Vec::<u8>::from(proto::Packet::construct_from(
                                                proto::PacketData::LoginFailure {
                                                    reason: "Login failed".to_string(),
                                                },
                                            )))
                                        }
                                        _ => Err(ReqError::Failed),
                                    }
                                } else {
                                    println!("Invalid session");
                                    Err(ReqError::Failed)
                                }
                            } else {
                                let session_id = auth::genrand();
                                let challenge = auth::genrand() as u32;
                                devices.insert(req.device_address, session_id);
                                sessions.insert(
                                    session_id,
                                    RwLock::new(Session::Login {
                                        sess_challenge: challenge,
                                        login_failed: false,
                                    }),
                                );

                                let packet = Packet::construct_from(PacketData::Hello {
                                    challenge,
                                    session_id,
                                });

                                println!("Sending hello packet");
                                Ok(Vec::<u8>::from(packet))
                            }
                        }
                        .boxed()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let _app_handle = adapter.serve_gatt_application(app).await?;
    println!("Service ready. Press enter to stop...");
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let _ = lines.next_line().await;

    println!("Stopping service...");

    Ok(())
}
/*
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //let packet = proto::Packet::new()?;
    let data = vec![
        0x49, 0xC8, 0xAB, 0x76, 0x82, 0x3F, 0xDE, 0x74, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 'a' as u8, 'b' as u8,
    ];
    let packet = proto::Packet::read_from(&mut data.as_slice()).await?;
    println!("{:?}", packet);

    let code = auth::genrand();
    let result = auth::checkcode(code, auth::encodecode(code));
    println!("Checkcode result: {}", result);
    Ok(())
}
*/
