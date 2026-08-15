//! Control plane.
//!
//! Every request is forwarded to the capture thread and answered from there,
//! so the answer always reflects a consistent point in the packet stream. In
//! particular `POST /captures` reports up front which connections it could not
//! vouch for, which is the difference between finding out now and finding out
//! after an hour of analysing output that was never trustworthy.

use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::capture::{Cmd, StartReq};

const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

pub fn serve(addr: &str, tx: Sender<Cmd>) -> Result<(), String> {
    let server = Server::http(addr).map_err(|e| format!("binding {addr}: {e}"))?;
    eprintln!("h2tapd: control api on http://{addr}");
    for mut req in server.incoming_requests() {
        let (code, body) = handle(&mut req, &tx);
        let hdr = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("static header");
        let resp = Response::from_string(body).with_header(hdr).with_status_code(code);
        let _ = req.respond(resp);
    }
    Ok(())
}

fn handle(req: &mut Request, tx: &Sender<Cmd>) -> (u16, String) {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/");
    let method = req.method().clone();

    match (&method, path) {
        (Method::Get, "/health") => ask(tx, Cmd::Health),
        (Method::Get, "/connections") => ask(tx, Cmd::Connections),

        (Method::Post, "/captures") => {
            let mut body = String::new();
            if req.as_reader().read_to_string(&mut body).is_err() {
                return (400, errj("could not read request body"));
            }
            let sreq: StartReq = if body.trim().is_empty() {
                StartReq::default()
            } else {
                match serde_json::from_str(&body) {
                    Ok(v) => v,
                    Err(e) => return (400, errj(&format!("bad json: {e}"))),
                }
            };
            ask_result(tx, move |reply| Cmd::Start { req: sreq, reply })
        }

        (Method::Delete, "/captures") => {
            ask_result(tx, |reply| Cmd::Stop { id: None, reply })
        }
        (Method::Delete, p) if p.starts_with("/captures/") => {
            let id = p.trim_start_matches("/captures/").to_string();
            ask_result(tx, move |reply| Cmd::Stop { id: Some(id), reply })
        }

        (Method::Get, "/") => (
            200,
            json!({
                "service": "h2tapd",
                "endpoints": [
                    "GET /health",
                    "GET /connections",
                    "POST /captures  {\"name\":..,\"pcap\":..,\"snapshot\":..}",
                    "DELETE /captures/{id}",
                ]
            })
            .to_string(),
        ),

        _ => (404, errj("not found")),
    }
}

fn ask<F>(tx: &Sender<Cmd>, make: F) -> (u16, String)
where
    F: FnOnce(Sender<Value>) -> Cmd,
{
    let (rtx, rrx) = channel();
    if tx.send(make(rtx)).is_err() {
        return (503, errj("capture thread is gone"));
    }
    match rrx.recv_timeout(REPLY_TIMEOUT) {
        Ok(v) => (200, v.to_string()),
        Err(_) => (504, errj("capture thread did not respond")),
    }
}

fn ask_result<F>(tx: &Sender<Cmd>, make: F) -> (u16, String)
where
    F: FnOnce(Sender<Result<Value, String>>) -> Cmd,
{
    let (rtx, rrx) = channel();
    if tx.send(make(rtx)).is_err() {
        return (503, errj("capture thread is gone"));
    }
    match rrx.recv_timeout(REPLY_TIMEOUT) {
        Ok(Ok(v)) => (200, v.to_string()),
        Ok(Err(e)) => (409, errj(&e)),
        Err(_) => (504, errj("capture thread did not respond")),
    }
}

fn errj(msg: &str) -> String {
    json!({ "error": msg }).to_string()
}
