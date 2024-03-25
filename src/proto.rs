use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;

const SIGNATURE: u64 = 0x74DE3F8276ABC849;

#[repr(u8)]
#[derive(Debug)]
enum PacketType {
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
enum PacketData {
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
    // ...
    length: u32,
    hash: u64,
    data: PacketData,
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

        let hash = reader.read_u64_le().await?;
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

                let mut username = Vec::with_capacity(username_length.into());
                AsyncReadExt::take(reader, username_length as u64)
                    .read_to_end(&mut username)
                    .await?;
                let username = String::from_utf8(username)?;
                println!("Username: {:?}", username);

                let mut password = Vec::with_capacity(password_length.into());
                AsyncReadExt::take(reader, password_length as u64)
                    .read_to_end(&mut password)
                    .await?;
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

        Ok(Packet {
            // ...
            length,
            hash,
            data,
        })
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        let mut data = Vec::new();
        // ...
        data
    }
}
