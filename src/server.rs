#![feature(uniform_paths)]

//!
//! This example showcases the Github OAuth2 process for requesting access to the user's public repos and
//! email address.
//!
//! Before running it, you'll need to generate your own Github OAuth2 credentials.
//!
//! In order to run the example call:
//!
//! ```sh
//! GITHUB_CLIENT_ID=xxx GITHUB_CLIENT_SECRET=yyy cargo run --example github
//! ```
//!
//! ...and follow the instructions.
//!


fn main() {
    env_logger::init();
    oauth_server();
    // let addr = server.addrs()[0];
    // println!("Running on: {:?}", addr);
    // server.run();

}

use actix_web::{http, server, App, HttpRequest, Query, Responder, State};
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
             TokenUrl};

use serde::{Deserialize, Serialize};
use serde_derive::{Deserialize, Serialize};

use std::env;
use std::sync::Mutex;

use url::Url;


struct AppState {
    pub csrf_tokens: Vec<CsrfToken>,
}

pub fn oauth_server() {// -> server::HttpServer<application::HttpApplication<AppState>> {
    server::new(|| {
        App::with_state(AppState { csrf_tokens: Vec::new() })
            .resource("/oauth-cli", |r| r.f(oauth_gen))
            .resource("/oauth-cli-fin", |r| r.method(http::Method::GET).with(oauth_fin))
    }).bind("127.0.0.1:8080").expect("could not bind to :8080").run()
}


#[derive(Debug, Deserialize, Serialize)]
struct OauthResp {
    port: u32,
    code: String,
    state: String,
}

fn oauth_gen(req: &HttpRequest<AppState>) -> impl Responder {
    let (url, token) = generate_authorization_url();

    // let mut tokens = req.state().csrf_tokens;//.lock().expect("failed to lock CSRF token store");
    // tokens.push(token);

    url.to_string()
}

fn oauth_fin((info, _state): (Query<OauthResp>, State<AppState>)) -> impl Responder {
    println!("Info: {:?}", info);
    REDIRECT_PAGE
}


fn generate_authorization_url() -> (Url, CsrfToken) {
    let github_client_id = ClientId::new(
        env::var("GITHUB_CLIENT_ID").expect("Missing the GITHUB_CLIENT_ID environment variable."),
    );
    let github_client_secret = ClientSecret::new(
        env::var("GITHUB_CLIENT_SECRET")
            .expect("Missing the GITHUB_CLIENT_SECRET environment variable."),
    );
    let auth_url = AuthUrl::new(
        Url::parse("https://github.com/login/oauth/authorize")
            .expect("Invalid authorization endpoint URL"),
    );
    let token_url = TokenUrl::new(
        Url::parse("https://github.com/login/oauth/access_token")
            .expect("Invalid token endpoint URL"),
    );

    // Set up the config for the Github OAuth2 process.
    let client = BasicClient::new(
            github_client_id,
            Some(github_client_secret),
            auth_url, Some(token_url)
        )
        .add_scope(Scope::new("read:user".to_string()))

        // This example will be running its own server at localhost:8080.
        // See below for the server implementation.
        .set_redirect_url(
            RedirectUrl::new(
                Url::parse(&format!("http://localhost:8080/oauth-cli-fin?port={}", 31415))
                    .expect("Invalid redirect URL")
            )
        );

    // Generate the authorization URL to which we'll redirect the user.
    client.authorize_url(CsrfToken::new_random)
}

const REDIRECT_PAGE: &'static str = "\
<html>
<body>
Woo! You are now authenticated.
</body>
</html>
";