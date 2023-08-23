#![warn(rust_2018_idioms)]

use atomic::Ordering::{Relaxed, SeqCst};
use bytes::Bytes;
use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use futures_util::future::join;
use hyper::header::{ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use log::info;
use mel_spec::mel::interleave_frames;
use mel_spec::quant::*;
use pretty_env_logger;
use serde_json::{json, to_string};
use std::net::SocketAddr;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{Method, Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::time::{interval, Duration};

use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use whisper::service::MelToText;

struct SttResult {
    text: String,
}

async fn api_handler(
    req: Request<hyper::body::Incoming>,
    whisper_mtx: &Mutex<i32>,
    tga_tx: UnboundedSender<Vec<u8>>,
    stt_rx: Arc<Mutex<UnboundedReceiver<SttResult>>>,
    stats: Arc<Mutex<Stats>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let models = stats.lock().await.models();
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => {
            let json_response = json!({
              "models": models,
              "queue": stats.lock().await.queue(),
              "done": stats.lock().await.done(),
            });
            let body = to_string(&json_response).expect("JSON serialization error");
            let mut res = Response::new(full(Bytes::from(body)).boxed());
            cors(&mut res);
            Ok(res)
        }
        (&Method::POST, "/") => {
            if models > 0 {
                let whole_body = req.collect().await.expect("body").to_bytes();
                stats.lock().await.inc();
                let text = {
                    // we can only process one input at a time on the whisper model
                    // TODO: a bounded(1) channel instead?
                    let _lock = whisper_mtx.lock().await;
                    let _ = tga_tx.send(whole_body.to_vec());

                    let stt_result = stt_rx.lock().await.recv().await.unwrap();
                    stt_result.text
                };
                let mut res = Response::new(full(Bytes::from(text)).boxed());
                stats.lock().await.dec();
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

struct Stats {
    n_in: AtomicUsize,
    n_out: AtomicUsize,
    models: AtomicUsize,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            n_in: AtomicUsize::new(0),
            n_out: AtomicUsize::new(0),
            models: AtomicUsize::new(0),
        }
    }
    pub fn inc(&mut self) {
        AtomicUsize::fetch_add(&self.n_in, 1, Relaxed);
    }

    pub fn dec(&mut self) {
        AtomicUsize::fetch_add(&self.n_out, 1, Relaxed);
    }

    pub fn done(&self) -> usize {
        AtomicUsize::load(&self.n_out, Relaxed)
    }

    pub fn queue(&self) -> usize {
        AtomicUsize::load(&self.n_in, Relaxed) - AtomicUsize::load(&self.n_out, Relaxed)
    }

    pub fn ready(&self) {
        AtomicUsize::fetch_add(&self.models, 1, Relaxed);
    }

    pub fn models(&self) -> usize {
        AtomicUsize::load(&self.models, Relaxed)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pretty_env_logger::init();

    let whisper_mutex = Arc::new(Mutex::new(0));
    let stats = Arc::new(Mutex::new(Stats::new()));

    let (loader_tx, loader_rx): (Sender<u8>, Receiver<u8>) = bounded(1);
    let (tga_tx, mut tga_rx) = unbounded_channel::<Vec<u8>>();
    let (stt_tx, mut stt_rx) = unbounded_channel::<SttResult>();
    let (tga2_tx, mut tga2_rx) = unbounded_channel::<Vec<u8>>();
    let (stt2_tx, mut stt2_rx) = unbounded_channel::<SttResult>();

    let stt2_rx_mutex = Arc::new(Mutex::new(stt2_rx));
    let stt_rx_mutex = Arc::new(Mutex::new(stt_rx));

    let addr: SocketAddr = ([0, 0, 0, 0], 1337).into();

    let stats_clone = stats.clone();
    let stats_clone_ready = stats.clone();

    let _ = tokio::task::spawn_blocking(move || {
        let model_name = "tiny_en".to_string();
        info!("loading model {:?}", model_name);

        let t = std::time::Instant::now();
        let whisper = MelToText::new(&model_name).unwrap();
        info!(
            "{:?} loaded in {:?} secs",
            model_name,
            t.elapsed().as_secs()
        );
        loader_tx.send(1).unwrap();
        tokio::spawn(async move {
            stats_clone_ready.lock().await.ready();
        });

        while let Some(tga) = tga_rx.blocking_recv() {
            if let Ok(frames) = parse_tga_8bit(&tga) {
                let arr = to_array2(&frames, 80);
                let padded = interleave_frames(&[arr], false, 1500);
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

    let stats_clone_ready2 = stats.clone();

    let _ = tokio::task::spawn_blocking(move || {
        // block waiting for first model to load
        let _ = loader_rx.recv();
        let model_name = "medium_en".to_string();
        info!("loading model {:?}", model_name);

        let t = std::time::Instant::now();
        let whisper = MelToText::new(&model_name).unwrap();
        info!(
            "{:?} loaded in {:?} secs",
            model_name,
            t.elapsed().as_secs()
        );
        tokio::spawn(async move {
            stats_clone_ready2.lock().await.ready();
        });

        while let Some(tga) = tga2_rx.blocking_recv() {
            if let Ok(frames) = parse_tga_8bit(&tga) {
                let arr = to_array2(&frames, 80);
                let padded = interleave_frames(&[arr], false, 1500);
                let text = whisper.add(&padded);
                let result = SttResult {
                    text: text.text().to_owned(),
                };
                if let Err(send_error) = stt2_tx.send(result) {
                    eprintln!("Error sending to stt out channel: {:?}", send_error);
                };
            }
        }
    });

    let srv = async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            // got a new connection
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);

            let tga_tx_clone;
            let stt_rx_clone;

            if stats_clone.lock().await.models() > 1 {
                info!("using model 2");
                tga_tx_clone = tga2_tx.clone();
                stt_rx_clone = stt2_rx_mutex.clone();
            } else {
                tga_tx_clone = tga_tx.clone();
                stt_rx_clone = stt_rx_mutex.clone();
            }

            let whisper_mutex_clone = whisper_mutex.clone();

            let stats_clone = stats_clone.clone();

            tokio::task::spawn(async move {
                let stats_clone_inside = stats_clone.clone();

                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|req| {
                            let stats_clone_inside = stats_clone_inside.clone(); // Clone for the inner closure
                            api_handler(
                                req,
                                &whisper_mutex_clone,
                                tga_tx_clone.clone(),
                                stt_rx_clone.clone(),
                                stats_clone_inside,
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

    info!("hush server listening on {:?}", addr);

    srv.await;

    Ok(())
}
