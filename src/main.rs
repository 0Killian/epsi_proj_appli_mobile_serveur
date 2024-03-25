// use std::error::Error;

mod proto;

// use bluer::{
//     adv::Advertisement,
//     gatt::local::{
//         Application, CharacteristicNotifyMethod, CharacteristicWrite, CharacteristicWriteMethod,
//         Service,
//     },
// };
// use std::sync::{Arc, Mutex};

// #[tokio::main]
/*
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the bluetooth daemon
    let session = bluer::Session::new().await?;

    // Get the default adapter
    let adapter = session.default_adapter().await?;

    // Advertise the adapter
    println!(
        "Advertising on Bluetooth adapter {} with address {}",
        adapter.name(),
        adapter.address()
    );

    let mut manufacturer_data = BTreeMap::new();
    manufacturer_data.insert(MANUFACTURER_ID, vec![0x21, 0x22, 0x23, 0x24]);
    let le_advertisement = Advertisement {
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        manufacturer_data,
        discoverable: Some(true),
        local_name: Some("Example Server".to_string()),
        ..Default::default()
    };
    let adv_handle = adapter.advertise(&le_advertisement).await?;

    println!(
        "Serving GATT service on bluetooth adapter {}",
        adapter.name()
    );
    let value = Arc::new(Mutex::new(vec![0x10, 0x01, 0x01, 0x10]));
    let value_read = value.clone();
    let value_write = value.clone();
    let value_notify = value.clone();
    let app = Application {
        services: vec![Service {
            uuid: SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: CHARACTERISTIC_UUID,
                read: Some(CharacteristicRead {
                    read: true,
                    fun: Box::new(move |req| {
                        let value = value_read.clone();
                        async move {
                            let value = value.lock().await.clone();
                            println!("Read request: {:?} with value {:x?}", &req, &value);
                            Ok(value)
                        }
                        .boxed()
                    }),
                    ..Default::default()
                }),
                write: Some(CharacteristicWrite {
                    write: true,
                    write_without_response: true,
                    method: CharacteristicWriteMethod::Fun(Box::new(move |new_value, req| {
                        let value = value_write.clone();
                        async move {
                            println!("Write request: {:?} with value {:x?}", &req, &new_value);
                            *value.lock().await = new_value;
                            Ok(())
                        }
                        .boxed()
                    })),
                    ..Default::default()
                }),
                notify: Some(CharacteristicNotify {
                    notify: true,
                    method: CharacteristicNotifyMethod::Fun(Box::new(move |mut notifier| {
                        let value = value_notify.clone();
                        async move {
                            tokio::spawn(async move {
                                println!(
                                    "Notification session start with confirming {:?}",
                                    notifier.confirming()
                                );
                                loop {
                                    {
                                        let mut value = value.lock().await;
                                        println!("Notifying with value {:x?}", &value);
                                        if let Err(err) = notifier.notify(value.to_vec).await {
                                            println!("Notification error: {}", &err);
                                            break;
                                        }
                                        println("Decrementing each element by one");
                                        for v in &mut value {
                                            *v = v.saturating_sub(1);
                                        }
                                    }
                                    tokio::time::sleep(Duration::from_secs(5)).await;
                                }
                                println!("Notification session stop");
                            });
                        }
                        .boxed()
                    })),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    let app_handle = adapter.serve_gatt_application(app).await?;
    println!("Service ready. Press enter to stop...");
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let _ = lines.next_line().await;

    println!("Stopping service...");

    Ok(())
}
*/
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    //let packet = proto::Packet::new()?;
    let data = vec![
        0x49, 0xC8, 0xAB, 0x76, 0x82, 0x3F, 0xDE, 0x74, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x01, 0x01, 'a' as u8,
        'b' as u8,
    ];
    let packet = proto::Packet::try_from(data)?;
    println!("{:?}", packet);
    Ok(())
}
