#![feature(uniform_paths)]

use actix_web::{http, server, App, HttpRequest, HttpResponse, Json, Query, Result, State};
use actix_web::middleware::session::RequestSession;
use actix_web::middleware::Logger;
use failure::Error;
use lazy_static::lazy_static;
use log::*;
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl,
    Scope, TokenUrl};
use serde_derive::Deserialize;
use std::path::PathBuf;
use url::Url;

use crate::msgs::*;
use crate::util::*;

#[derive(Clone, Debug, Deserialize)]
enum Provider {
    Github,
    Custom {
        /// URL to authorize the OAuth2.0 request
        #[serde(with="serde_newtype_url")]
        pub auth_url: AuthUrl,

        /// URL to recover the OAuth2.0 token given a successful
        /// authorization.
        #[serde(with="serde_newtype_url")]
        pub token_url: TokenUrl,
    }
}

/// Configuration data to parse from TOML
#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    /// OAuth2 Client ID
    #[serde(with="serde_newtype")]
    pub client_id: ClientId,

    /// OAuth2 Client application secret
    #[serde(with="serde_secret_newtype")]
    pub client_secret: ClientSecret,

    /// Port on which to run the server
    pub port: u16,

    /// Endpoint for the server callback.
    /// Should route to this server:
    /// `http://127.0.0.1:{port}/oauth-cli/finish`
    #[serde(with="url_serde")]
    pub server_url: Url,

    /// Scopes to authorize.
    #[serde(with="serde_newtype_vec")]
    pub scopes: Vec<Scope>,

    /// HTML webpage template to serve when the client finishes 
    #[serde(with="url_serde")]
    pub welcome_redirect: Url,
}

fn main() {
    run_oauth_proxy();
}

struct AppState {
    // pub csrf_tokens: Vec<CsrfToken>,
    // pub config: Config,
    pub oauth_client: BasicClient,
}

impl AppState {
    fn from_config(config: Config) -> Self {
        let Config {
            client_id,
            client_secret,
            port,
            server_url,
            auth_url,
            token_url,
            scopes,
            welcome_redirect,
        } = config;
        // Set up the config for the Github OAuth2 process.
        let mut client = BasicClient::new(
            client_id,
            Some(client_secret),
            auth_url,
            Some(token_url),
        );
        for scope in scopes {
            client = client.add_scope(scope);
        }
        Self {
            oauth_client: client,
        }
    }
}

/// Runs a proxy server which generates a single-use
/// OAuth2 path for the client, and handles finishing the auth.
pub fn run_oauth_proxy(config: &Config) {
    let port = config.port;
    server::new(|| {
        App::with_state(AppState::from_config(config.clone()))
            .middleware(Logger::default())
            .resource("/oauth-cli/start", |r| r.method(http::Method::POST).with(oauth_gen))
            .resource("/oauth-cli/finish", |r| r.method(http::Method::GET).with(oauth_fin))
    })
    .workers(1)
    .bind(&format!("127.0.0.1:{}", port))
    .expect(&format!("could not bind to {}", port))
    .run()
}


fn oauth_gen((params, state): (Json<GenParams>, State<AppState>)) -> String {
    debug!("Received params: {:#?}", params);
    generate_authorization_url(
        params.into_inner(),
        state.oauth_client.clone()
    ).map(|u| u.to_string()).unwrap()
}

fn oauth_fin((req, info, state): (HttpRequest<AppState>, Query<FinParams>, State<AppState>)) -> HttpResponse {
    let token = state.oauth_client.exchange_code(info.code.clone()).unwrap();
    req.session().set("access_token", token.access_token().secret().to_string());
    req.session().set("shared_secret", "abc".to_string());
    // req.session().set("scopes", token.access_token().secret().to_string());
    let redirect_url = Url::parse(
        &format!("http://localhost:{}?state={}&new_secret=abc",
            info.client_port,
            info.csrf_token.secret()
        )
    ).unwrap();

    get_redirect_page(redirect_url)
}

fn generate_authorization_url(params: GenParams, client: BasicClient) -> Result<Url, Error>  { 
    let config = Config::get_global();
    let client = client.set_redirect_url(
        RedirectUrl::new(
            Url::parse(
                &format!(
                    "{}oauth-cli/finish?client_port={}",
                    config.server_url,
                    params.client_port,
                )
            )?
        )
    );

    // Generate the authorization URL to which we'll redirect the user.
    Ok(client.authorize_url(|| params.csrf_token).0)
}


fn get_redirect_page(redirect_url: Url) -> HttpResponse {
    let html = include_str!("redirect_template.html");
    let html = html.replace("{{redirect_url}}", &redirect_url.to_string());

    HttpResponse::Ok()
        .body(html)
}
