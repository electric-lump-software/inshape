//! Test doubles: a scripted fake Infisical server and a fake CONNECT proxy.
//! Both listen on loopback with an OS-chosen port.

#![allow(dead_code)]

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    pub delay: Duration,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn json(status: u16, body: &str) -> Reply {
        Reply::bytes(status, body.as_bytes().to_vec())
    }

    pub fn bytes(status: u16, body: Vec<u8>) -> Reply {
        Reply {
            status,
            body,
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Reply {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn delayed(mut self, delay: Duration) -> Reply {
        self.delay = delay;
        self
    }
}

#[derive(Clone, Debug)]
pub struct Route {
    method: String,
    path: String,
    query: Option<(String, String)>,
    reply: Reply,
}

pub fn route(method: &str, path: &str, reply: Reply) -> Route {
    Route {
        method: method.to_owned(),
        path: path.to_owned(),
        query: None,
        reply,
    }
}

impl Route {
    pub fn when_query(mut self, key: &str, value: &str) -> Route {
        self.query = Some((key.to_owned(), value.to_owned()));
        self
    }

    fn matches(&self, req: &Recorded) -> bool {
        self.method == req.method
            && self.path == req.path
            && self
                .query
                .as_ref()
                .is_none_or(|(k, v)| req.query_pairs().iter().any(|(qk, qv)| qk == k && qv == v))
    }
}

#[derive(Clone, Debug)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn query_pairs(&self) -> Vec<(String, String)> {
        if self.query.is_empty() {
            return Vec::new();
        }
        self.query
            .split('&')
            .map(|pair| {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                (percent_decode(k), percent_decode(v))
            })
            .collect()
    }

    pub fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("request body is JSON")
    }
}

pub struct FakeInfisical {
    port: u16,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl FakeInfisical {
    pub fn start(routes: Vec<Route>) -> FakeInfisical {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
        let port = listener.local_addr().expect("local addr").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = serve_one(stream, &routes, &log);
            }
        });
        FakeInfisical { port, requests }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr())
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("lock").clone()
    }
}

fn serve_one(stream: TcpStream, routes: &[Route], log: &Mutex<Vec<Recorded>>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let head = read_head(&mut reader)?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default();
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;

    let req = Recorded {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        headers,
        body,
    };
    let reply = routes
        .iter()
        .find(|r| r.matches(&req))
        .map(|r| r.reply.clone())
        .unwrap_or_else(|| Reply::json(404, r#"{"message":"no route"}"#));
    log.lock().expect("lock").push(req);

    thread::sleep(reply.delay);
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {} Fake\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        reply.status,
        reply.body.len()
    )?;
    for (name, value) in &reply.headers {
        write!(out, "{name}: {value}\r\n")?;
    }
    out.write_all(b"\r\n")?;
    out.write_all(&reply.body)?;
    out.flush()
}

fn read_head(reader: &mut impl BufRead) -> io::Result<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if reader.read(&mut byte)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&head).trim_end().to_owned())
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Default)]
struct ProxyLog {
    auth_seen: bool,
    targets: Vec<String>,
}

pub struct FakeProxy {
    port: u16,
    log: Arc<Mutex<ProxyLog>>,
}

impl FakeProxy {
    pub fn start(expect_auth: Option<&str>) -> FakeProxy {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake proxy");
        let port = listener.local_addr().expect("local addr").port();
        let log = Arc::new(Mutex::new(ProxyLog::default()));
        let shared = Arc::clone(&log);
        let expected = expect_auth.map(|creds| format!("Basic {}", base64(creds.as_bytes())));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let shared = Arc::clone(&shared);
                let expected = expected.clone();
                thread::spawn(move || {
                    let _ = tunnel(stream, expected.as_deref(), &shared);
                });
            }
        });
        FakeProxy { port, log }
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    pub fn auth_seen(&self) -> bool {
        self.log.lock().expect("lock").auth_seen
    }

    pub fn targets(&self) -> Vec<String> {
        self.log.lock().expect("lock").targets.clone()
    }
}

fn tunnel(client: TcpStream, expected: Option<&str>, log: &Mutex<ProxyLog>) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(client.try_clone()?);
    let head = read_head(&mut reader)?;
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_owned();
    let auth = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.trim().to_owned());
    if auth.is_some() {
        log.lock().expect("lock").auth_seen = true;
    }
    let mut out = client.try_clone()?;
    let target = match request_line.strip_prefix("CONNECT ") {
        Some(rest) => rest.split(' ').next().unwrap_or_default().to_owned(),
        None => {
            out.write_all(b"HTTP/1.1 405 Fake\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
    };
    if let Some(expected) = expected
        && auth.as_deref() != Some(expected)
    {
        out.write_all(
            b"HTTP/1.1 407 Fake\r\nProxy-Authenticate: Basic realm=\"fake\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        return Ok(());
    }
    let upstream = TcpStream::connect(&target)?;
    log.lock().expect("lock").targets.push(target);
    out.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;

    let mut up_read = upstream.try_clone()?;
    let mut up_write = upstream;
    let pump = thread::spawn(move || {
        let _ = io::copy(&mut reader, &mut up_write);
        let _ = up_write.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut up_read, &mut out);
    let _ = out.shutdown(std::net::Shutdown::Both);
    let _ = pump.join();
    Ok(())
}

pub fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub struct PlainHttpListener {
    port: u16,
}

impl PlainHttpListener {
    pub fn start() -> PlainHttpListener {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 400 Fake\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        PlainHttpListener { port }
    }

    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

pub fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local addr").port()
}
