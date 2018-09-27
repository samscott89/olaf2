//! Functionality for authenticating a client
//!
//! The `Client` has 3 main responsibilities:
//!
//!  - Query the `Proxy` for an authz URL.
//!  - Prompt the `User` to visit the URL (either automtically opening the URL,
//!    or through copy+paste).
//!  - Wait for the `User` to be redirected back to the locally running
//!    HTTP server.

use actix::Addr;
use actix_web::{
    http, 
    server::{self, Server},
    App, HttpResponse, Query, State
};
use lazy_static::lazy_static;
use log::*;
use oauth2::CsrfToken;
use oauth2::prelude::*;
use serde::{de::DeserializeOwned, Serialize};
use serde_derive::Deserialize;
use std::ops::Deref;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use url::Url;

use crate::msgs::*;
use crate::util::*;

/// Run the authn process for proxy running at `proxy_url`.
pub fn authenticate<R>(proxy_url: &str) -> String
    where R: 'static + DeserializeOwned + Serialize
{
    let sys = actix::System::new("oauth_cli");  // <- create Actix system
    let token = CsrfToken::new_random();
    let (tx, rx) = mpsc::sync_channel(1);
    let tx = Arc::new(tx);
    let (port, server) = run_oauth_listener::<R>(Arc::new(token.clone()), tx);
    let params = GenParams {
        client_port: port,
        csrf_token: token,
    };
    let url = get_authorization_url(&params, Url::parse(proxy_url).unwrap());
    // info!("Recovered URL: {}", url);
    println!("Attempting to open URL in browser");
    let failed = match open::that(url.to_string()) {
            Ok(s) if s.success() => false,
            Ok(_) => { println!("Failed to find browser to open URL."); true },
            Err(_) => { println!("Couldn't find native 'open` command"); true },
    };
    if failed {
        println!(
            "Open this URL in your browser:\n{}\n",
            url.to_string()
        );
    }

    let current_system = actix::System::current();
    let arbiter = current_system.arbiter().clone();
    let arc_secret = Arc::new(Mutex::new(String::new()));
    let arc_secret2 = arc_secret.clone();
    thread::spawn(move || {
        println!("Waiting to receive secret...");
        let (secret, sys) = rx.recv().unwrap();
        actix::System::set_current(sys.clone());
        info!("New secret received: {}", secret);
        *arc_secret2.lock().unwrap() = secret;
        server.do_send(actix_web::server::StopServer { graceful: false });
        sys.stop();
    });
    sys.run();  // <- Run actix system, this method starts all async processes

    let secret = arc_secret.lock().unwrap();
    // arc_secret.lock().unwrap().clone().to_string()
    secret.clone()
}

type ChannelMsg = (String, actix::System);

#[derive(Clone, Debug)]
struct AppState {
    // server_url: String,
    nonce: Arc<CsrfToken>,
    tx: Arc<mpsc::SyncSender<ChannelMsg>>,
}

fn run_oauth_listener<R>(nonce: Arc<CsrfToken>, tx: Arc<mpsc::SyncSender<ChannelMsg>>) -> (u16, Addr<Server>)
    where R: 'static + DeserializeOwned + Serialize
{
    let state = AppState { nonce, tx };

    let server = server::new(move || {
        App::with_state(state.clone()).resource("/", |r| r.with(handle_response::<R>))
    })
    .workers(1)
    .bind("127.0.0.1:0")
    .expect("Can not bind to 127.0.0.1:0");
    let port = server.addrs().get(0).unwrap().port();

    (port, server.start())
}

fn handle_response<R>((info, state): (Query<FinResponse<R>>, State<AppState>)) -> HttpResponse
    where R: 'static + DeserializeOwned + Serialize
{
    // info!("Info: {:#?}", info);
    let FinResponse { csrf_token, response, welcome_redirect } = info.into_inner();
    info!("Received nonce: {}, Expected nonce: {}", csrf_token.secret(), state.nonce.secret());
    // info!("new_secret: {}", new_secret);
    if &csrf_token == state.nonce.deref() {
        info!("CSRF tokens match");
        state.tx.send((serde_json::to_string(&response).unwrap(), actix::System::current())).unwrap();
    } else {
        state.tx.send(("Incorrect tokens".to_string(), actix::System::current())).unwrap();
    }

    if let Some(welcome) = welcome_redirect {
        let html = super::get_redirect_page(welcome.deref(), welcome.deref());
        HttpResponse::Ok()
            .connection_type(http::ConnectionType::Close)
            .body(html)
    } else {
        HttpResponse::Ok()
            .connection_type(http::ConnectionType::Close)
            .finish()
    }
}

fn get_authorization_url(params: &GenParams, server_url: Url) -> String {
    // let server_url = &Config::get_global().server_url;
    let client = reqwest::Client::new();
    let resp = client.post(&format!("{}oauth-cli/start", server_url))
                     .json(params)
                     .send(); 
    info!("Response: {:#?}", resp);
    resp.unwrap().text().unwrap()
}
