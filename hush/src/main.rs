use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Method;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crossbeam_channel::{bounded, unbounded, Receiver, Sender};
use mel_spec::mel::interleave_frames;
use mel_spec::quant::*;
use std::thread;
use structopt::StructOpt;

use whisper::service::MelToText;

#[derive(Debug, StructOpt)]
#[structopt(name = "hush", about = "hush")]
struct Command {
    #[structopt(short, long, default_value = "tiny_en")]
    model_name: String,
}

async fn handler(
    req: Request<hyper::body::Incoming>,
    tga_tx: Sender<Vec<u8>>,
    stt_rx: Receiver<SttResult>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() == Method::POST {
        let whole_body = req.collect().await.expect("body").to_bytes();
        tga_tx
            .send(whole_body.to_vec())
            .expect("Failed to send TGA data for processing");

        let stt_result = stt_rx.recv().expect("Failed to receive STT result");

        let mut response = Response::new(Full::new(Bytes::from(stt_result.text)));
        response
            .headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
        response.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            "GET, POST, OPTIONS".parse().unwrap(),
        );
        Ok(response)
    } else {
        let response = Response::new(Full::new(Bytes::from("OK")));
        Ok(response)
    }
}

struct SttResult {
    text: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let args = Command::from_args();
    let model_name = args.model_name;
    let (tga_tx, tga_rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = bounded(1);
    let (stt_tx, stt_rx): (Sender<SttResult>, Receiver<SttResult>) = unbounded();

    thread::spawn(move || {
        dbg!(&model_name);
        let whisper = MelToText::new(&model_name).expect("failed to load model");
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

    let addr = SocketAddr::from(([0, 0, 0, 0], 9000));

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);
        let tga_tx_clone = tga_tx.clone();
        let stt_rx_clone = stt_rx.clone();

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(|req| handler(req, tga_tx_clone.clone(), stt_rx_clone.clone())),
                )
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}
