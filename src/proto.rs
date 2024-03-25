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
        Challenge: u32,
    },
    Login {
        Username: String,
        Password: String,
        Challenge: u32,
    },
    LoginSuccess {
        SessionId: u64,
    },
    LoginFailure {
        Reason: String,
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

impl Packet {}

impl TryFrom<Vec<u8>> for Packet {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> anyhow::Result<Self> {
        if data.len() < 21 {
            return Err(anyhow::anyhow!("Packet is too short"));
        }

        let signature = u64::from_le_bytes(data[0..8].try_into()?);
        if signature != SIGNATURE {
            return Err(anyhow::anyhow!("Invalid packet signature"));
        }

        let length = u32::from_le_bytes(data[8..12].try_into()?);
        if data.len() < length as usize + 21 {
            return Err(anyhow::anyhow!("Packet is too short"));
        }

        let hash = u64::from_le_bytes(data[12..20].try_into()?);

        let packet_type = PacketType::try_from(data[20])?;

        println!("Signature: {:x}", signature);
        println!("Length: {}", length);
        println!("Hash: {:x}", hash);
        println!("Packet type: {:?}", packet_type);

        let data = match packet_type {
            PacketType::Hello => {
                anyhow::bail!("Hello is only sent by the server");
            }
            PacketType::Login => {
                if length < 8 {
                    return Err(anyhow::anyhow!("Packet is too short"));
                }

                let challenge = u32::from_le_bytes(data[21..25].try_into()?);
                let username_length = u8::from_le_bytes(data[25..26].try_into()?);
                let password_length = u8::from_le_bytes(data[26..27].try_into()?);

                println!("Challenge: {}", challenge);
                println!("Username length: {}", username_length);
                println!("Password length: {}", password_length);

                if length < 6u32 + username_length as u32 + password_length as u32 {
                    return Err(anyhow::anyhow!("Packet is too short"));
                }

                let username =
                    String::from_utf8(data[21 + 6..21 + 6 + username_length as usize].to_vec())?;
                let password = String::from_utf8(
                    data[21 + 6 + username_length as usize
                        ..21 + 6 + username_length as usize + password_length as usize]
                        .to_vec(),
                )?;

                PacketData::Login {
                    Username: username,
                    Password: password,
                    Challenge: challenge,
                }
            }
            PacketType::LoginSuccess => {
                anyhow::bail!("LoginSuccess is only sent by the server");
            }
            PacketType::LoginFailure => {
                anyhow::bail!("LoginFailure is only sent by the server");
            }
        };

        // ...
        Ok(Packet { length, hash, data })
    }
}

impl From<Packet> for Vec<u8> {
    fn from(packet: Packet) -> Vec<u8> {
        let mut data = Vec::new();
        // ...
        data
    }
}
