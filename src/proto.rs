use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;

const SIGNATURE: u64 = 0x74DE3F8276ABC849;

#[repr(u8)]
#[derive(Debug)]
pub enum PacketType {
    Hello = 0,
    Login = 1,
    LoginSuccess = 2,
    LoginFailure = 3,
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> anyhow::Result<Self> {
        match value {
            0 => Ok(PacketType::Hello),
            1 => Ok(PacketType::Login),
            2 => Ok(PacketType::LoginSuccess),
            3 => Ok(PacketType::LoginFailure),
            _ => Err(anyhow::anyhow!("Invalid packet type")),
        }
    }
}

#[derive(Debug)]
pub enum PacketData {
    Hello {
        challenge: u32,
        session_id: u64,
        // Raw representation:
        // | challenge (4 bytes) | session_id (8 bytes) |
    },
    Login {
        username: String,
        password: String,
        challenge: u32,
        session_id: u64,
        // Raw representation:
        // | challenge (4 bytes) | username_length (1 byte) | password_length (1 byte) | session_id (8 bytes) | username (variable length) | password (variable length) |
    },
    LoginSuccess {},
    LoginFailure {
        reason: String,
        // Raw representation:
        // | reason_length (1 byte) | reason (variable length) |
    },
}

#[derive(Debug)]
#[repr(C)]
pub struct Packet {
    pub length: u32,
    pub hash: u8,
    pub data: PacketData,
}

impl Packet {
    pub async fn read_from<R>(reader: &mut R) -> anyhow::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        // Read base packet fields
        let signature = reader.read_u64_le().await?;
        if signature != SIGNATURE {
            return Err(anyhow::anyhow!("Invalid packet signature"));
        }

        println!("Signature: {:?}", signature);

        let length = reader.read_u32_le().await?;
        println!("Length: {:?}", length);

        let hash = reader.read_u8().await?;
        println!("Hash: {:?}", hash);

        let packet_type = PacketType::try_from(reader.read_u8().await?)?;
        println!("Packet type: {:?}", packet_type);

        // Read type-specific data
        let mut inner_data = Vec::with_capacity(length as usize);
        reader
            .take(length as u64)
            .read_to_end(&mut inner_data)
            .await?;
        println!("Inner data: {:?}", inner_data);

        let computed_hash = compute_hash(inner_data.clone());
        if computed_hash != hash {
            return Err(anyhow::anyhow!(format!(
                "Invalid packet hash, expected: {:?}, computed: {:?}",
                hash, computed_hash
            )));
        }

        let data = match packet_type {
            PacketType::Hello => {
                anyhow::bail!("Hello is only sent by the server");
            }
            PacketType::Login => {
                let mut reader = inner_data.as_slice();
                let challenge = reader.read_u32_le().await?;
                println!("Challenge: {:?}", challenge);
                let username_length = reader.read_u8().await?;
                println!("Username length: {:?}", username_length);
                let password_length = reader.read_u8().await?;
                println!("Password length: {:?}", password_length);
                let session_id = reader.read_u64_le().await?;
                println!("Session ID: {:?}", session_id);

                let mut username = Vec::with_capacity(username_length as usize);
                username.extend_from_slice(&reader[..username_length as usize]);
                let username = String::from_utf8(username)?;
                println!("Username: {:?}", username);
                let reader = &reader[username_length as usize..];

                let mut password = Vec::with_capacity(password_length.into());
                password.extend_from_slice(&reader[..password_length as usize]);
                let password = String::from_utf8(password)?;
                println!("Password: {:?}", password);

                PacketData::Login {
                    username,
                    password,
                    challenge,
                    session_id,
                }
            }
            PacketType::LoginSuccess => {
                anyhow::bail!("LoginSuccess is only sent by the server");
            }
            PacketType::LoginFailure => {
                anyhow::bail!("LoginFailure is only sent by the server");
            }
        };

        Ok(Packet { length, hash, data })
    }

    pub fn construct_from(data: PacketData) -> Self {
        let packet_data: Vec<u8> = Vec::<u8>::from(&data);
        Packet {
            length: packet_data.len() as u32,
            hash: compute_hash(packet_data),
            data,
        }
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        Vec::<u8>::from(&packet)
    }
}

impl From<&Packet> for Vec<u8> {
    fn from(packet: &Packet) -> Vec<u8> {
        let mut data = Vec::new();

        // Signature
        data.extend_from_slice(&SIGNATURE.to_le_bytes());

        // Length
        data.extend_from_slice(&packet.length.to_le_bytes());

        // Hash
        data.extend_from_slice(&packet.hash.to_le_bytes());

        // Packet type
        match packet.data {
            PacketData::Hello { .. } => {
                data.push(PacketType::Hello as u8);
            }
            PacketData::Login { .. } => {
                data.push(PacketType::Login as u8);
            }
            PacketData::LoginSuccess {} => {
                data.push(PacketType::LoginSuccess as u8);
            }
            PacketData::LoginFailure { .. } => {
                data.push(PacketType::LoginFailure as u8);
            }
        }

        // Inner data
        data.extend_from_slice(&(Vec::<u8>::from(&packet.data)));

        data
    }
}

impl From<PacketData> for Vec<u8> {
    fn from(packet: PacketData) -> Vec<u8> {
        Vec::<u8>::from(&packet)
    }
}

impl From<&PacketData> for Vec<u8> {
    fn from(packet: &PacketData) -> Vec<u8> {
        let mut data = Vec::new();

        // Packet data
        match packet {
            PacketData::Hello {
                challenge,
                session_id,
            } => {
                data.extend_from_slice(&challenge.to_le_bytes());
                data.extend_from_slice(&session_id.to_le_bytes());
            }
            PacketData::Login {
                username,
                password,
                challenge,
                session_id,
            } => {
                data.extend_from_slice(&challenge.to_le_bytes());
                data.push(username.len() as u8);
                data.push(password.len() as u8);
                data.extend_from_slice(&session_id.to_le_bytes());
                data.extend_from_slice(username.as_bytes());
                data.extend_from_slice(password.as_bytes());
            }
            PacketData::LoginSuccess {} => {}
            PacketData::LoginFailure { reason } => {
                data.push(reason.len() as u8);
                data.extend_from_slice(reason.as_bytes());
            }
        }

        data
    }
}

fn compute_hash(data: Vec<u8>) -> u8 {
    let mut hash: u8 = 0;

    for d in data {
        hash = hash.wrapping_add(d);
    }

    255 - hash
}
