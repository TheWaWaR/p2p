use futures::{channel, StreamExt};
use std::{
    thread,
    time::{Duration, Instant},
};
use tentacle::{
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    error::Error,
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, SessionType,
        TargetProtocol,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};

pub fn create<F>(secio: bool, meta: ProtocolMeta, shandle: F) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    let builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    if secio {
        builder
            .key_pair(SecioKeyPair::secp256k1_generated())
            .build(shandle)
    } else {
        builder.build(shandle)
    }
}

#[derive(Clone, Copy, Debug)]
enum ServiceErrorType {
    Dialer,
    Listen,
}

#[derive(Clone)]
struct EmptySHandle {
    sender: crossbeam_channel::Sender<ServiceErrorType>,
    secio: bool,
}

impl ServiceHandle for EmptySHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        use std::io;

        let error_type = if let ServiceError::DialerError { error, .. } = error {
            match error {
                Error::IoError(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused),
                e => panic!("test fail {}", e),
            }
            ServiceErrorType::Dialer
        } else {
            panic!("test fail {:?}", error);
        };
        let _ = self.sender.try_send(error_type);
    }
}

#[derive(Clone)]
pub struct SHandle {
    sender: crossbeam_channel::Sender<ServiceErrorType>,
    secio: bool,
    session_id: SessionId,
    kind: SessionType,
}

impl ServiceHandle for SHandle {
    fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        let error_type = match error {
            ServiceError::DialerError { error, .. } => {
                if self.kind.is_inbound() {
                    match error {
                        Error::ConnectSelf => (),
                        _ => panic!("server test fail: {:?}", error),
                    }
                } else {
                    match error {
                        Error::RepeatedConnection(id) => assert_eq!(id, self.session_id),
                        _ => panic!("client test fail: {:?}", error),
                    }
                }
                ServiceErrorType::Dialer
            }
            ServiceError::ListenError { error, .. } => {
                assert_eq!(error, Error::RepeatedConnection(self.session_id));
                ServiceErrorType::Listen
            }
            _ => panic!("test fail"),
        };

        let _ = self.sender.try_send(error_type);
    }

    fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { session_context } = event {
            self.session_id = session_context.id;
            self.kind = session_context.ty;
        }
    }
}

struct PHandle {
    connected_count: usize,
    sender: crossbeam_channel::Sender<usize>,
    dial_count: usize,
    dial_addr: Option<Multiaddr>,
}

impl ServiceProtocol for PHandle {
    fn init(&mut self, context: &mut ProtocolContext) {
        let proto_id = context.proto_id;
        let _ = context.set_service_notify(proto_id, Duration::from_secs(1), 3);
    }

    fn connected(&mut self, context: ProtocolContextMutRef, _version: &str) {
        if context.session.ty.is_inbound() {
            // if server, dial itself
            self.dial_addr = Some(context.listens()[0].clone());
        } else {
            // if client, dial server
            self.dial_addr = Some(context.session.address.clone());
        }
        self.connected_count += 1;
    }

    fn disconnected(&mut self, _context: ProtocolContextMutRef) {
        self.connected_count -= 1;
    }

    fn notify(&mut self, context: &mut ProtocolContext, _token: u64) {
        if self.dial_addr.is_some() {
            let _ = context.dial(
                self.dial_addr.as_ref().unwrap().clone(),
                TargetProtocol::All,
            );
            self.dial_count += 1;
            if self.dial_count == 10 {
                self.sender.try_send(self.connected_count).unwrap();
            }
        }
    }
}

fn create_meta(id: ProtocolId) -> (ProtocolMeta, crossbeam_channel::Receiver<usize>) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::Neither
            } else {
                let handle = Box::new(PHandle {
                    connected_count: 0,
                    sender,
                    dial_count: 0,
                    dial_addr: None,
                });
                ProtocolHandle::Callback(handle)
            }
        })
        .build();

    (meta, receiver)
}

fn create_shandle(
    secio: bool,
    empty: bool,
) -> (
    Box<dyn ServiceHandle + Send>,
    crossbeam_channel::Receiver<ServiceErrorType>,
) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    if empty {
        (Box::new(EmptySHandle { sender, secio }), receiver)
    } else {
        (
            Box::new(SHandle {
                sender,
                secio,
                session_id: 0.into(),
                kind: SessionType::Inbound,
            }),
            receiver,
        )
    }
}

fn check_dial_errors(
    receiver: crossbeam_channel::Receiver<ServiceErrorType>,
    timeout: Duration,
    expected: usize,
) -> usize {
    let now = Instant::now();
    for i in 0..expected {
        loop {
            if receiver.try_recv().is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
            if now.elapsed() > timeout {
                return i;
            }
        }
    }
    expected
}

fn test_repeated_dial(secio: bool) {
    let (meta_1, receiver_1) = create_meta(1.into());
    let (meta_2, receiver_2) = create_meta(1.into());
    let (shandle, error_receiver_1) = create_shandle(secio, false);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta_1, shandle);
        rt.spawn(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            let _ = addr_sender.send(listen_addr);
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
        rt.shutdown_on_idle();
    });

    let (shandle, error_receiver_2) = create_shandle(secio, false);

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(secio, meta_2, shandle);
        rt.spawn(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
        rt.shutdown_on_idle();
    });

    if secio {
        assert_eq!(receiver_1.recv(), Ok(1));
        assert_eq!(receiver_2.recv(), Ok(1));
        assert_eq!(
            check_dial_errors(error_receiver_1, Duration::from_secs(30), 10),
            10
        );
        assert_eq!(
            check_dial_errors(error_receiver_2, Duration::from_secs(30), 10),
            10
        );
    } else {
        assert_ne!(receiver_1.recv(), Ok(1));
        assert_ne!(receiver_2.recv(), Ok(1));
        assert!(error_receiver_1.is_empty());
        assert!(error_receiver_2.is_empty());
    }
}

fn test_dial_with_no_notify(secio: bool) {
    let (meta, _receiver) = create_meta(0.into());
    let (shandle, error_receiver) = create_shandle(secio, true);
    let mut service = create(secio, meta, shandle);
    let control = service.control().clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.spawn(async move {
            loop {
                if service.next().await.is_none() {
                    break;
                }
            }
        });
        rt.shutdown_on_idle();
    });
    // macOs can't dial 0 port
    for _ in 0..2 {
        for i in 1..6 {
            let addr = format!("/ip4/127.0.0.1/tcp/{}", i).parse().unwrap();
            control.dial(addr, TargetProtocol::All).unwrap();
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    assert_eq!(
        check_dial_errors(error_receiver, Duration::from_secs(15), 10),
        10
    );
}

#[test]
fn test_repeated_dial_with_secio() {
    test_repeated_dial(true)
}

#[test]
fn test_repeated_dial_with_no_secio() {
    test_repeated_dial(false)
}

#[test]
fn test_dial_no_notify_with_secio() {
    test_dial_with_no_notify(true)
}

#[test]
fn test_dial_no_notify_with_no_secio() {
    test_dial_with_no_notify(false)
}
