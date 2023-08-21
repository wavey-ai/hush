#![warn(rust_2018_idioms)]

use atomic::Ordering::{Relaxed, SeqCst};
use bytes::Bytes;
use crossbeam_channel::{unbounded, Receiver, Sender};
use futures_util::future::join;
use hyper::header::{ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use mel_spec::mel::interleave_frames;
use mel_spec::quant::*;
use serde_json::{json, to_string};
use std::net::SocketAddr;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::time::{interval, Duration};

use std::sync::Arc;
use structopt::StructOpt;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use whisper::service::MelToText;

#[derive(Debug, StructOpt)]
#[structopt(name = "hush", about = "hush")]
struct Command {
    #[structopt(short, long, default_value = "tiny_en")]
    model_name: String,
}

struct SttResult {
    text: String,
}

async fn api_handler(
    req: Request<hyper::body::Incoming>,
    ready: bool,
    whisper_mtx: &Mutex<i32>,
    tga_tx: Sender<Vec<u8>>,
    stt_rx: Receiver<SttResult>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let json_response = json!({
              "ready": ready,
            });
            let body = to_string(&json_response).expect("JSON serialization error");
            let mut res = Response::new(full(Bytes::from(body)).boxed());
            cors(&mut res);
            Ok(res)
        }
        (&Method::POST, "/") => {
            if ready {
                let whole_body = req.collect().await.expect("body").to_bytes();
                let text = {
                    // we can only process one input at a time on the whisper model
                    // TODO: a bounded(1) channel instead?
                    let _lock = whisper_mtx.lock().await;
                    tga_tx
                        .send(whole_body.to_vec())
                        .expect("Failed to send TGA data for processing");

                    let stt_result = stt_rx.recv().expect("Failed to receive STT result");
                    stt_result.text
                };
                let mut res = Response::new(full(Bytes::from(text)).boxed());
                cors(&mut res);
                Ok(res)
            } else {
                let mut res = Response::new(empty());
                *res.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                cors(&mut res);
                Ok(res)
            }
        }
        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn cors(response: &mut Response<BoxBody<Bytes, hyper::Error>>) {
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
}
fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let whisper_mutex = Arc::new(Mutex::new(0));
    let args = Command::from_args();
    let model_name = args.model_name;

    let ready_mutex = Arc::new(Mutex::new(false));

    // TODO: use tokio channels here?
    let (tga_tx, tga_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
    let (stt_tx, stt_rx): (Sender<SttResult>, Receiver<SttResult>) = unbounded();
    let (ready_tx, mut ready_rx) = oneshot::channel();
    let ready_clone = Arc::clone(&ready_mutex);

    let _ = tokio::task::spawn_blocking(move || {
        dbg!(&model_name);
        let whisper = MelToText::new(&model_name).expect("failed to load model");
        tokio::spawn(async move {
            if let Err(_) = ready_tx.send(1) {
                println!("the receiver dropped");
            }
        });

        println!("Ready...");

        while let Ok(tga) = tga_rx.recv() {
            if let Ok(frames) = parse_tga_8bit(&tga) {
                let arr = to_array2(&frames, 80);
                let padded = interleave_frames(&[arr], false, 3000);
                let text = whisper.add(&padded);
                let result = SttResult {
                    text: text.text().to_owned(),
                };
                if let Err(send_error) = stt_tx.send(result) {
                    eprintln!("Error sending to stt out channel: {:?}", send_error);
                };
            }
        }
    });

    let addr: SocketAddr = ([0, 0, 0, 0], 1337).into();

    let ready_clone_srv = Arc::clone(&ready_mutex);
    let srv = async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);

            let ready_mutex_guard = ready_clone_srv.lock().await;
            let ready_clone = ready_mutex_guard.clone();
            let tga_tx_clone = tga_tx.clone();
            let stt_rx_clone = stt_rx.clone();
            let whisper_mutex_clone = whisper_mutex.clone();

            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req| {
                            api_handler(
                                req,
                                ready_clone,
                                &whisper_mutex_clone,
                                tga_tx_clone.clone(),
                                stt_rx_clone.clone(),
                            )
                        }),
                    )
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    };

    println!("Listening on http://{}", addr,);

    let loop_handle: JoinHandle<()> = tokio::spawn(async move {
        let dur = Duration::from_millis(100);
        let mut interval = interval(dur);
        loop {
            tokio::select! {

                _ = interval.tick() => {},
                _ = &mut ready_rx => {
                    *ready_clone.lock().await = true;
                    break;
                }
            }
        }
    });

    tokio::join!(srv, loop_handle);
    Ok(())
}
