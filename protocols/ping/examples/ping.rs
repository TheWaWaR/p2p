use env_logger;
use log::{debug, info};

use std::time::Duration;

use futures::{
    channel::mpsc::{channel, Sender},
    prelude::*,
    StreamExt,
};
use p2p::{
    builder::{MetaBuilder, ServiceBuilder},
    context::ServiceContext,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, ServiceError, ServiceEvent, TargetProtocol},
    traits::ServiceHandle,
    ProtocolId,
};
use tentacle_ping::{Event, PingHandler};

fn main() {
    env_logger::init();
    let rt = tokio::runtime::Runtime::new().unwrap();
    if std::env::args().nth(1) == Some("server".to_string()) {
        debug!("Starting server ......");
        let (sender, mut receiver) = channel(256);
        let protocol = create_meta(
            1.into(),
            Duration::from_secs(5),
            Duration::from_secs(15),
            sender,
        );
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .key_pair(SecioKeyPair::secp256k1_generated())
            .forever(true)
            .build(SimpleHandler {});
        rt.spawn(async move {
            loop {
                match receiver.next().await {
                    Some(event) => info!("server receive event: {:?}", event),
                    None => break,
                }
            }
        });
        rt.spawn(async move {
            service
                .listen("/ip4/127.0.0.1/tcp/1337".parse().unwrap())
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    } else {
        debug!("Starting client ......");
        let (sender, mut receiver) = channel(256);
        let protocol = create_meta(
            1.into(),
            Duration::from_secs(5),
            Duration::from_secs(15),
            sender,
        );
        let mut service = ServiceBuilder::default()
            .insert_protocol(protocol)
            .key_pair(SecioKeyPair::secp256k1_generated())
            .forever(true)
            .build(SimpleHandler {});
        rt.spawn(async move {
            loop {
                match receiver.next().await {
                    Some(event) => info!("server receive event: {:?}", event),
                    None => break,
                }
            }
        });
        rt.spawn(async move {
            service
                .dial(
                    "/ip4/127.0.0.1/tcp/1337".parse().unwrap(),
                    TargetProtocol::All,
                )
                .await
                .unwrap();
            service
                .listen("/ip4/127.0.0.1/tcp/1338".parse().unwrap())
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
    }

    rt.shutdown_on_idle();
}

pub fn create_meta(
    id: ProtocolId,
    interval: Duration,
    timeout: Duration,
    event_sender: Sender<Event>,
) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(PingHandler::new(interval, timeout, event_sender));
            ProtocolHandle::Callback(handle)
        })
        .build()
}

struct SimpleHandler {}

impl ServiceHandle for SimpleHandler {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        debug!("service error: {:?}", error);
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        debug!("service event: {:?}", event);
    }
}
