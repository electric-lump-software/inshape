//! The Infisical client. Response bodies and ureq's own error text are never shown,
//! and the proxy is always set explicitly, so `HTTP(S)_PROXY` is ignored.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use ureq::http::Response;
use ureq::{Agent, Body, Proxy};

use crate::config::Settings;
use crate::{Error, Secret, VERSION};

const TIMEOUT: Duration = Duration::from_secs(10);
const BODY_LIMIT: u64 = 1024 * 1024;
/// ureq fails once it has read `limit` bytes, even at the end of the body, so
/// reading allows one byte more than the largest body accepted.
const READ_LIMIT: u64 = BODY_LIMIT + 1;

const LOGIN_PATH: &str = "/api/v1/auth/universal-auth/login";
const SECRETS_PATH: &str = "/api/v4/secrets";
const REVOKE_PATH: &str = "/api/v1/auth/token/revoke";

const SIGN_IN: &str = "sign-in";
const ANSWERED: &str = "Infisical answered HTTP ";
const REVOKING: &str = "revoking the token";

#[derive(Debug)]
pub struct RawSecret {
    pub key: String,
    pub value: Secret,
    pub environment: Option<String>,
    pub secret_path: Option<String>,
    pub value_hidden: bool,
}

pub struct Client {
    http: Agent,
    api_url: String,
    client_id: String,
    client_secret: Secret,
    project_id: String,
    env: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("api_url", &self.api_url)
            .field("project_id", &self.project_id)
            .field("env", &self.env)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    #[serde(rename = "clientId")]
    client_id: &'a str,
    #[serde(rename = "clientSecret")]
    client_secret: &'a str,
}

#[derive(Deserialize)]
struct LoginResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
}

#[derive(Serialize)]
struct RevokeRequest<'a> {
    #[serde(rename = "accessToken")]
    access_token: &'a str,
}

#[derive(Deserialize)]
struct SecretsResponse {
    secrets: Vec<WireSecret>,
}

#[derive(Deserialize)]
struct WireSecret {
    #[serde(rename = "secretKey")]
    secret_key: String,
    #[serde(rename = "secretValue")]
    secret_value: String,
    #[serde(default)]
    environment: Option<String>,
    #[serde(rename = "secretPath", default)]
    secret_path: Option<String>,
    #[serde(rename = "secretValueHidden", default)]
    secret_value_hidden: Option<bool>,
}

impl Client {
    pub fn new(settings: &Settings) -> Result<Client, Error> {
        let proxy = match &settings.proxy_url {
            Some(url) => Some(Proxy::new(url.expose()).map_err(|_| {
                Error::Config("INFISICAL_PROXY_URL could not be used as a proxy".to_owned())
            })?),
            None => None,
        };
        let config = Agent::config_builder()
            .proxy(proxy)
            .timeout_global(Some(TIMEOUT))
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(format!("inshape/{VERSION}"))
            .build();
        Ok(Client {
            http: Agent::new_with_config(config),
            api_url: settings.api_url.clone(),
            client_id: settings.client_id.clone(),
            client_secret: settings.client_secret.clone(),
            project_id: settings.project_id.clone(),
            env: settings.env.clone(),
        })
    }

    pub fn login(&self) -> Result<Secret, Error> {
        let body = to_json(&LoginRequest {
            client_id: &self.client_id,
            client_secret: self.client_secret.expose(),
        });
        let result = self
            .http
            .post(format!("{}{LOGIN_PATH}", self.api_url))
            .header("Content-Type", "application/json")
            .send(&body[..]);
        let bytes = read(SIGN_IN, result)?;
        let parsed: LoginResponse = parse(SIGN_IN, &bytes)?;
        if parsed.access_token.is_empty() {
            return Err(Error::Refused(format!(
                "{SIGN_IN}: the response had an empty accessToken"
            )));
        }
        Ok(Secret::new(parsed.access_token))
    }

    pub fn fetch(&self, token: &Secret, path: &str) -> Result<Vec<RawSecret>, Error> {
        let purpose = format!("fetching {path}");
        let result = self
            .http
            .get(format!("{}{SECRETS_PATH}", self.api_url))
            .query("projectId", &self.project_id)
            .query("environment", &self.env)
            .query("secretPath", path)
            .query("expandSecretReferences", "false")
            .query("includeImports", "false")
            .query("recursive", "false")
            .query("viewSecretValue", "true")
            .header("Authorization", format!("Bearer {}", token.expose()))
            .call();
        let bytes = read(&purpose, result)?;
        let parsed: SecretsResponse = parse(&purpose, &bytes)?;
        Ok(parsed
            .secrets
            .into_iter()
            .map(|s| RawSecret {
                key: s.secret_key,
                value: Secret::new(s.secret_value),
                environment: s.environment,
                secret_path: s.secret_path,
                value_hidden: s.secret_value_hidden.unwrap_or(false),
            })
            .collect())
    }

    pub fn revoke(&self, token: &Secret) -> Result<(), Error> {
        let body = to_json(&RevokeRequest {
            access_token: token.expose(),
        });
        let result = self
            .http
            .post(format!("{}{REVOKE_PATH}", self.api_url))
            .header("Content-Type", "application/json")
            .send(&body[..]);
        read(REVOKING, result).map(|_| ())
    }
}

pub fn http_status(err: &Error) -> Option<u16> {
    let (_, rest) = err.message().split_once(ANSWERED)?;
    rest.parse().ok()
}

fn to_json(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("a struct of strings always serialises")
}

fn read(purpose: &str, result: Result<Response<Body>, ureq::Error>) -> Result<Vec<u8>, Error> {
    let mut response = result.map_err(|e| transport_error(purpose, &e))?;
    let status = response.status().as_u16();
    match status {
        200..=299 => {}
        401 | 403 => {
            return Err(Error::Auth(format!("{purpose}: {ANSWERED}{status}")));
        }
        500..=599 => {
            return Err(Error::Unavailable(format!("{purpose}: {ANSWERED}{status}")));
        }
        _ => {
            return Err(Error::Refused(format!("{purpose}: {ANSWERED}{status}")));
        }
    }
    response
        .body_mut()
        .with_config()
        .limit(READ_LIMIT)
        .read_to_vec()
        .map_err(|e| transport_error(purpose, &e))
}

fn parse<T: for<'de> Deserialize<'de>>(purpose: &str, bytes: &[u8]) -> Result<T, Error> {
    serde_json::from_slice(bytes)
        .map_err(|_| Error::Refused(format!("{purpose}: the response was not the expected JSON")))
}

/// ureq's own messages can hold the URL, so only fixed text is shown.
fn transport_error(purpose: &str, err: &ureq::Error) -> Error {
    use ureq::Error as E;
    let unavailable = |what: &str| Error::Unavailable(format!("{purpose}: {what}"));
    match err {
        E::BodyExceedsLimit(_) => {
            Error::Refused(format!("{purpose}: the response body is over 1 MiB"))
        }
        E::Timeout(_) => unavailable("timed out after 10 s"),
        E::ConnectProxyFailed(_) | E::InvalidProxyUrl => {
            unavailable("the proxy refused or failed the connection")
        }
        E::Tls(_) | E::TlsRequired | E::Rustls(_) | E::Pem(_) => unavailable("TLS failed"),
        E::HostNotFound => unavailable("could not resolve the host"),
        E::ConnectionFailed => unavailable("could not connect"),
        E::Io(io) => match io.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                unavailable("timed out after 10 s")
            }
            std::io::ErrorKind::ConnectionRefused => unavailable("connection refused"),
            std::io::ErrorKind::InvalidData => unavailable("TLS or the connection failed"),
            _ => unavailable("the connection failed"),
        },
        E::Protocol(_) | E::LargeResponseHeader(..) => {
            unavailable("the response was not valid HTTP")
        }
        _ => unavailable("the request failed"),
    }
}
