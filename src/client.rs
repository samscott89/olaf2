#![feature(uniform_paths)]

use abscissa::{impl_global_config, logging, CanonicalPathBuf, GlobalConfig};
use actix_web::{http, server, App, HttpResponse, Query, State};
use lazy_static::lazy_static;
use log::*;
use oauth2::CsrfToken;
use oauth2::prelude::*;
use serde_derive::Deserialize;
use std::ops::Deref;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use url::Url;

use olaf2::*;

/// Configuration data to parse from TOML
#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    /// Endpoint for the server.
    #[serde(with="url_serde")]
    pub server_url: Url,
}

impl_global_config!(Config, SERVER_CONFIG);

fn main() {
    let config = logging::LoggingConfig::default();
    logging::init(config).expect("failed to start logging");

    Config::set_global(Config { server_url: Url::parse("http://localhost:8081").unwrap() });

    let token = CsrfToken::new_random();
    let (tx, rx) = mpsc::sync_channel(1);
    let tx = Arc::new(tx);
    let port = run_oauth_listener(Arc::new(token.clone()), tx);
    let params = GenParams {
        client_port: port,
        csrf_token: token,
    };
    let url = get_authorization_url(&params);
    info!("Recovered URL: {}", url);
    if open::that(url.to_string()).is_err() {
        println!(
            "Open this URL in your browser:\n{}\n",
            url.to_string()
        );
    }

    let secret = rx.recv().unwrap();
    info!("New secret received: {}", secret);

}

#[derive(Clone, Debug)]
struct AppState {
    nonce: Arc<CsrfToken>,
    tx: Arc<mpsc::SyncSender<String>>,
}

pub fn run_oauth_listener(nonce: Arc<CsrfToken>, tx: Arc<mpsc::SyncSender<String>>) -> u16 {
    let state = AppState { nonce, tx };

    let server = server::new(move || {
        App::with_state(state.clone()).resource("/", |r| r.with(handle_response))
    })
    .workers(1)
    .bind("127.0.0.1:0")
    .expect("Can not bind to 127.0.0.1:0");
    let port = server.addrs().get(0).unwrap().port();

    thread::spawn(move || {
        let sys = actix::System::new("oauth_cli");  // <- create Actix system
        server.start();
        sys.run();  // <- Run actix system, this method starts all async processes
    });

    port
}

fn handle_response((info, state): (Query<FinResponse>, State<AppState>)) -> HttpResponse {
    info!("Info: {:#?}", info);
    let FinResponse { csrf_token, new_secret} = info.into_inner();
    info!("Received nonce: {}, Expected nonce: {}", csrf_token.secret(), state.nonce.secret());
    info!("new_secret: {}", new_secret);
    if &csrf_token == state.nonce.deref() {
        state.tx.send(new_secret).unwrap();
    } else {
        state.tx.send("".to_string()).unwrap();
    }
    HttpResponse::Ok()
        .connection_type(http::ConnectionType::Close) // <- Close connection
        .force_close()                                // <- Alternative method
        .finish()
}

pub fn get_authorization_url(params: &GenParams) -> String {
    let server_url = &Config::get_global().server_url;
    let client = reqwest::Client::new();
    let resp = client.post(&format!("{}oauth-cli/start", server_url))
                     .json(params)
                     .send(); 
    info!("Response: {:#?}", resp);
    resp.unwrap().text().unwrap()
}
