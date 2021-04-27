#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub(crate) use anyhow::{anyhow as anyerror, Result as AnyResult};
pub(crate) use log::info;

use actix::{Actor, StreamHandler};
use actix_web::middleware::Logger as ActixLogger;
use actix_web::web::{get, resource, route, Data as SharedState, Payload, PayloadConfig};
use actix_web::{main as actix_main, App, HttpRequest, HttpResponse, HttpServer, Responder};
use actix_web_actors::ws::{
    start as wsclient_start, CloseCode, CloseReason, Message as WebsocketMessage,
    ProtocolError as WebsocketProtocolError, WebsocketContext,
};
use bytestring::ByteString;
use env_logger::builder as log_builder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs::OpenOptions;
use std::io::Read;
use std::sync::Mutex;
use tapa_trait_serde::IYamlSerializable;
use uuid::Uuid;

const RUST_LOG: &str = "RUST_LOG";

pub trait IHandshakeInterceptor: Sized + Sync {
    type Result: Default + PartialEq + Eq;

    #[allow(unused_variables)]
    fn intercept_handshake(&mut self, handshake_request: &HttpRequest) -> AnyResult<Self::Result> {
        Ok(Default::default())
    }
}

pub trait IStreamInterceptor: Sized + Sync {
    type Result: Default + PartialEq + Eq;

    #[allow(unused_variables)]
    fn intercept_string_stream(&mut self, string_stream: &ByteString) -> AnyResult<Self::Result> {
        Ok(Default::default())
    }
}

#[derive(Deserialize, IYamlSerializable, Serialize)]
struct Authenticator {
    permitted_jwt_tokens: HashMap<String, Uuid>,
    permitted_payload_prefix: String,
    verified_users: BTreeSet<Uuid>,
}

impl Authenticator {
    fn load_from_config() -> AnyResult<Self> {
        let mut loaded_config = String::new();
        OpenOptions::new().read(true).open("./config.yaml")?.read_to_string(&mut loaded_config)?;
        let mut loaded_config = Self::from_yaml_string(&loaded_config)?;
        loaded_config.verified_users = BTreeSet::new();

        Ok(loaded_config)
    }

    fn print_verified_users(&self) {
        info!("{:#?}", self.verified_users)
    }

    fn add_verified_user(&mut self, id: Uuid) -> bool {
        self.verified_users.insert(id)
    }

    fn del_verified_user(&mut self, id: &Uuid) -> bool {
        self.verified_users.remove(id)
    }
}

impl IHandshakeInterceptor for Authenticator {
    type Result = Uuid;

    fn intercept_handshake(&mut self, handshake_request: &HttpRequest) -> AnyResult<Self::Result> {
        let headers = handshake_request.headers();

        if let Some(auth_header) = headers.get("Authorization") {
            if let Ok(auth_value) = auth_header.to_str() {
                let jwt_token = auth_value.trim().replace("Bearer ", "");

                if let Some(user_id) = self.permitted_jwt_tokens.get(&jwt_token) {
                    return Ok(*user_id);
                }
            }
        }

        Err(anyerror!("Forbidden!"))
    }
}

impl IStreamInterceptor for Authenticator {
    type Result = String;

    fn intercept_string_stream(&mut self, string_stream: &ByteString) -> AnyResult<Self::Result> {
        let string_stream = string_stream.to_string();

        if let Some(purified_string) = string_stream.strip_prefix(&self.permitted_payload_prefix) {
            Ok(purified_string.to_owned())
        } else {
            Err(anyerror!("Forbidden!"))
        }
    }
}

async fn reject_unmapped_handler() -> impl Responder {
    HttpResponse::NotFound().body("Nothing to look here...")
}

async fn websocket_handshake(
    shared_state: SharedState<Mutex<Authenticator>>,
    request: HttpRequest,
    stream: Payload,
) -> impl Responder {
    let shared_state_clone = shared_state.clone();
    let mut shared_state = shared_state.lock().unwrap();

    if let Ok(user_id) = shared_state.intercept_handshake(&request) {
        if shared_state.add_verified_user(user_id) {
            shared_state.print_verified_users();
            wsclient_start(
                WebsocketClient { id: user_id, shared_state: shared_state_clone },
                &request,
                stream,
            )
        } else {
            HttpResponse::AlreadyReported().await
        }
    } else {
        HttpResponse::Forbidden().await
    }
}

fn init_logger(debug_mode: bool) {
    if env::var(RUST_LOG).is_err() {
        #[cfg(debug_assertions)]
        {
            if debug_mode {
                env::set_var(RUST_LOG, "trace");
            } else {
                env::set_var(RUST_LOG, "debug");
            }
        }
        #[cfg(not(debug_assertions))]
        {
            if debug_mode {
                env::set_var(RUST_LOG, "info");
            } else {
                env::set_var(RUST_LOG, "warn");
            }
        }
    }

    log_builder().default_format().format_timestamp_nanos().format_indent(Some(4)).init();
}

struct WebsocketClient {
    id: Uuid,
    shared_state: SharedState<Mutex<Authenticator>>,
}

impl Actor for WebsocketClient {
    type Context = WebsocketContext<Self>;

    fn stopped(&mut self, _: &mut Self::Context) {
        let mut shared_state = self.shared_state.lock().unwrap();
        shared_state.del_verified_user(&self.id);
        shared_state.print_verified_users();
    }
}

impl StreamHandler<Result<WebsocketMessage, WebsocketProtocolError>> for WebsocketClient {
    fn handle(
        &mut self,
        message: Result<WebsocketMessage, WebsocketProtocolError>,
        ctx: &mut Self::Context,
    ) {
        match message {
            Ok(WebsocketMessage::Ping(ping_message)) => ctx.pong(&ping_message),
            Ok(WebsocketMessage::Binary(_)) => ctx.close(Some(CloseReason {
                code: CloseCode::Unsupported,
                description: Some("Binary protocol is unsupported!".into()),
            })),
            Ok(WebsocketMessage::Text(text_message)) => {
                let mut shared_state = self.shared_state.lock().unwrap();

                if let Ok(parsed_message) = shared_state.intercept_string_stream(&text_message) {
                    ctx.text(format!("[ECHO] {}", parsed_message));
                } else {
                    ctx.text("[DENIED]");
                }
            }
            Ok(WebsocketMessage::Close(close_reason)) => ctx.close(close_reason),
            _ => info!("{:#?}", message),
        }
    }
}

#[actix_main]
async fn main() -> AnyResult<()> {
    init_logger(true);

    let authenticator = Authenticator::load_from_config()?;
    let authenticator = Mutex::new(authenticator);
    let authenticator = SharedState::new(authenticator);

    Ok(HttpServer::new(move || {
        let authenticator = authenticator.clone();

        App::new()
            .app_data(authenticator)
            .app_data(PayloadConfig::new(8 * 1024 * 1024))
            .wrap(ActixLogger::default())
            .service(resource("/ws").route(get().to(websocket_handshake)))
            .default_service(route().to(reject_unmapped_handler))
    })
    .client_timeout(500)
    .client_shutdown(500)
    .shutdown_timeout(1)
    .bind("0.0.0.0:4678")
    .unwrap()
    .run()
    .await?)
}
