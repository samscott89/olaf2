//! Functionality for running the proxy server.
//! 
//! The proxy server is responsible for generating an 
//! authorization URL for the client ("resource owner") to visit.
//!
//! On visiting this URL, the client will be asked to give authorization
//! to the application by the OAuth 2.0 provider. Successful authz
//! results in the client being redirected back to the proxy server.
//! Here, the final OAuth params are supplied to the proxy server in the
//! URL.
//!
//! These params also include a local port, which the client should be
//! listening on waiting for the final information from the proxy.
//!


use ::actix::prelude::*;
// use actix_web::dev::Handler;

use actix_web::{http, server, App, Either, FutureResponse, HttpRequest,
HttpResponse, Json, Query, Responder, Result, State};
use actix_web::AsyncResponder;
use actix_web::middleware::session::RequestSession;
use actix_web::middleware::Logger;
use failure::Error;
use futures::prelude::*;
use futures::future;
use lazy_static::lazy_static;
use log::*;
use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{AccessToken, AuthUrl, ClientId, ClientSecret, RedirectUrl,
    Scope, TokenUrl};
use serde::{Deserialize, de::DeserializeOwned, Serialize};
use serde_derive::{Deserialize, Serialize};
use url::Url;

use std::fmt::Debug;
use std::marker::{PhantomData, Send};
use std::ops::Deref;

use crate::server::Provider;
use crate::msgs::*;
use crate::util::*;

/// Proxy configuration values.
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

    /// Authorization provider
    pub oauth_provider: Provider,

    /// Endpoint for the server callback.
    /// Should route to this proxy:
    /// `http://127.0.0.1:{port}/oauth-cli/finish`
    #[serde(with="url_serde")]
    pub proxy_url: Url,

    /// Scopes to authorize.
    #[serde(with="serde_newtype_vec")]
    pub scopes: Vec<Scope>,

    /// HTML webpage template to serve when the client finishes 
    #[serde(with="url_serde")]
    pub welcome_redirect: Url,
}

/// Runs a proxy server which generates a single-use
/// OAuth2 path for the client, and handles finishing the auth.
///
/// Takes a closure instead of a Handler
pub fn run_with<F, R>(config: Config, session_handler: F)
    where F: 'static + Send + Fn(AccessToken) -> Result<R, Error>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize,
{
    run(config, ClosureHandler(session_handler, PhantomData))
}

/// Runs a proxy server which generates a single-use
/// OAuth2 path for the client, and handles finishing the auth.
pub fn run<H, R>(config: Config, session_handler: H)
    where H: SessionHandler<R>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize,
{
    let _sys = actix::System::new("olaf2-server");
    let port = config.port;
    let client_addr = OAuthExecutor::from_config(config);
    let session_handler = Arbiter::start(move |_| session_handler);
    server::new(move || {
        App::with_state(
            AppState { 
                oauth_client: client_addr.clone(),
                session_handler: session_handler.clone(),
                marker: PhantomData,
            })
            .middleware(Logger::default())
            .resource("/oauth-cli/start", 
                |r| r.method(http::Method::POST)
                     .with(oauth_gen))
            .resource("/oauth-cli/finish", 
                |r| r.method(http::Method::GET)
                     .with(oauth_fin))
    })
    // .workers(1)
    .bind(&format!("127.0.0.1:{}", port))
    .expect(&format!("could not bind to {}", port))
    .run()
}


impl Handler<GenParams> for OAuthExecutor {
    type Result = Result<Url, Error>;

    fn handle(&mut self, msg: GenParams, _: &mut Self::Context) -> Self::Result {
        use std::mem;
        // This is unfortunate due to oauth-rs API always taking `self`.
        if let Some(client) = self.client.take() {
            mem::replace(&mut self.client, 
                Some(client.set_redirect_url(
                    RedirectUrl::new(
                        Url::parse(
                            &format!(
                                "{}oauth-cli/finish?client_port={}",
                                self.config.proxy_url,
                                msg.client_port,
                            )
                        // TODO: replace with proper URL construction
                        ).expect("invalid proxy url provided") 
                    )
                ))
            );
            Ok(self.client.as_ref().unwrap().authorize_url(|| msg.csrf_token).0)
        } else {
            panic!("Missing client");
        }
    }
}

impl Handler<FinParams> for OAuthExecutor {
    type Result = Result<AccessToken, Error>;

    fn handle(&mut self, msg: FinParams, _: &mut Self::Context) -> Self::Result {
        Ok(self.client.as_mut().expect("missing client").exchange_code(msg.code)?.access_token().clone())
    }
}


/// Generates the authorization URL for the client to use.
/// (This needs to be done on the proxy side, since it uses
/// the OAuth 2.0 `client_secret`).
fn oauth_gen<H, R>((params, state): (Json<GenParams>, State<AppState<H, R>>))
    ->  impl Responder
    where H: SessionHandler<R>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize,
{
    debug!("Received params: {:#?}", params);
    state.oauth_client
        .send(params.into_inner())
        .from_err::<Error>()
        .and_then(|res| match res {
            Ok(url) => Ok(HttpResponse::Ok().body(url.to_string())),
            Err(_) => return Ok(HttpResponse::InternalServerError().into()),
        }).responder()
}

/// Complete the authorization handshake by exchanging the
/// auth code with a token. Finally creates the client "callback"
/// by redirecting the client to the server listening on localhost
fn oauth_fin<H, R>((info, state): (Query<FinParams>, State<AppState<H, R>>)) -> impl Responder
    where H: SessionHandler<R>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize,
{
    let port = info.client_port;
    let nonce = info.csrf_token.clone();
    state.oauth_client
    .send(info.into_inner())
    .from_err()
    .and_then(move |res: Result<AccessToken, _>| {
        match res {
            Ok(token) => {
                Either::A(state.session_handler.send(Token(token, PhantomData))
                .map(move |resp: Result<R, _>| {
                    match resp {
                        Ok(val) => {
                            let resp = FinResponse {
                                csrf_token: nonce,
                                response: val,
                            };
                            let redirect_url = Url::parse(
                                &format!("http://localhost:{}?{}",
                                    port,
                                    serde_qs::to_string(&resp).unwrap()
                                )   
                            ).unwrap();

                            get_redirect_page(redirect_url)
                        },
                        Err(_) => HttpResponse::InternalServerError().finish(),
                    }
                }))
            },
            Err(_) => Either::B(future::ok(HttpResponse::InternalServerError().finish())),
        }
    }).responder()
}

fn get_redirect_page(redirect_url: Url) -> HttpResponse {
    let html = include_str!("redirect_template.html");
    let html = html.replace("{{redirect_url}}", &redirect_url.to_string());

    HttpResponse::Ok()
        .body(html)
}


///// Annoying stuff

#[derive(Clone, Debug)]
struct OAuthExecutor {
    client: Option<BasicClient>,
    config: Config,
}

impl Actor for OAuthExecutor {
    type Context = Context<Self>;
}

impl Message for GenParams {
    type Result = Result<Url, Error>;
}

impl Message for FinParams {
    type Result = Result<AccessToken, Error>;
}

/// Type to allow generic handling of the `AccessToken`
/// into any suitable type `R`.
pub struct Token<R>(pub AccessToken, pub(crate) PhantomData<R>);

impl<R: 'static + Debug + DeserializeOwned + Send> Message for Token<R> {
    type Result = Result<R, Error>;
}

/// Trait to encapsulate handle `AccessToken`s output after completing
/// the auth process.
pub trait SessionHandler<R>: Handler<Token<R>> + Actor<Context=Context<Self>> + Send
    where R: 'static + Debug + DeserializeOwned + Send + Serialize
{ }


#[derive(Clone)]
struct AppState<H, R>
    where H: SessionHandler<R>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize,
{
    // pub config: Config,
    pub oauth_client: Addr<OAuthExecutor>,
    pub session_handler: Addr<H>,
    pub marker: PhantomData<R>,
}

impl OAuthExecutor {
    fn from_config(config: Config) -> Addr<Self> {
        let Config {
            client_id,
            client_secret,
            port,
            proxy_url,
            oauth_provider,
            scopes,
            welcome_redirect,
        } = config.clone();

        let (auth_url, token_url) = oauth_provider.into_urls();
        let mut client = BasicClient::new(
            client_id,
            Some(client_secret),
            auth_url,
            Some(token_url),
        );
        for scope in scopes {
            client = client.add_scope(scope);
        }
        let client = Self { client: Some(client), config: config };

        Arbiter::start(move |_| client.clone())
    }
}

impl<R> Deref for Token<R> {
    type Target = AccessToken;
    fn deref(&self) -> &AccessToken {
        &self.0
    }
}


struct ClosureHandler<
    F: Fn(AccessToken) -> Result<R, Error>,
    R: 'static + Debug + DeserializeOwned + Send + Sized + Serialize>(F, PhantomData<R>);

impl<F, R> Actor for ClosureHandler<F, R>
    where F: 'static + Fn(AccessToken) -> Result<R, Error>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize + Sized
{
    type Context = Context<Self>;
}

impl<F, R> Handler<Token<R>> for ClosureHandler<F, R>
    where F: 'static + Fn(AccessToken) -> Result<R, Error>,
          R: 'static + Debug + DeserializeOwned + Send + Serialize + Sized
{
    type Result = Result<R, Error>;

    fn handle(&mut self, msg: Token<R>, _: &mut Self::Context) -> Self::Result {
        (self.0)(msg.0)
    }
}

impl<F, R> SessionHandler<R> for ClosureHandler<F, R>
    where F: 'static + Fn(AccessToken) -> Result<R, Error> + Send,
          R: 'static + Debug + DeserializeOwned + Send + Serialize + Sized  
 {}