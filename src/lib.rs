//! Olaf2 is a library for conveniently authenticating
//! command-line applications using OAuth 2.0 via a proxy server.
//!
//! Note that OAuth 2.0 is an _authorization_ (authz) protocol, not 
//! an authentication (authn) protocol. OpenID Connect is designed 
//! as an authn protocol on top of OAuth 2.0, but is not widely deployed.
//!
//! Olaf2 provides an form of authentication by authorizing the
//! proxy server to retrieve the end-user's identity.
//! For example, using the Github provider, the proxy receives
//! a token which can be used with the Github API to recover the
//! user's github account name.
//!
//! Olaf2 can also be used to recover the OAuth 2.0 token
//! for accessing resources locally.
//!
//! A lot of the heavy lifting is done by the
//! [oauth2-rs](https://crates.io/crates/oauth2) crate. 
//!
//! ## Terminology
//!
//! The "Server" refers to the OAuth 2.0 authorization server, 
//! and is implemented externally to Olaf2. We provide some
//! preconfigured servers to connect to.
//! 
//! The "Proxy" refers to the OAuth 2.0 client, which receives the
//! authn and authz from the Server.
//!
//! The "Client" refers to the command line application, which
//! becomes authenticated by running the protocol.
//!
//! The "User" refers to the OAuth 2.0 resource owner, who wishes
//! to authenticate the CLI application, and visits URLs in a browser.
//!
//! ## Usage
//!
//! ### Proxy server
//! 
//! Obtain client id/secret values by visiting the auth provider website.
//! 
//! Configure the proxy, for example:
//! 
//! ```toml
//! # in proxy_config.toml
//! client_id = "deadbeefcafe1337"
//! client_secret = "somesecretvalue"
//! port = 8081
//! proxy_url = "http://localhost:8081/"
//! oauth_provider = "Github"
//! scopes = ["read:user", "user:email", "read:org"]
//! welcome_redirect = "http://localhost:8080/"
//! ```
//! Run the proxy with
//! 
//! ```rust
//!	use olaf2::*;
//! use toml;
//!
//! // the lazy way to load the config...
//! let toml = include_str!("proxy_config.toml");
//! let config: proxy::Config = toml::from_str(toml).unwrap();
//! proxy::run_with(config, |token| {
//!  	// This simple function prints the access token and
//!		// returns it to the client
//! 	let secret = token.secret().to_string();
//! 	println!("Received token: {}", &secret);
//! 	Ok(secret)
//! });
//! ```
//!
//! In this example, we are creating a session token handler
//! which simply prints the access token and returns the `String`
//! to the client. 
//!
//! On the other end of the connection, we need to tell the client
//! to accept a `String`.
//!
//! ### Client
//!
//! Simply run the client with:
//! ```rust
//! let secret = client::authenticate::<String>("http://127.0.0.1:8081");
//! println!("Secret: {}", secret); 
//! ```
//! 
//! Note: the proxy server returns a `String` from the closure, so we
//! specify the same type parameter for `authenticate`.
//! 
//! ## Details
//! 
//! The protocol flow works as follows:
//! 
//! 1. The `Client` starts a local HTTP server on a random port.
//! makes a get request to `proxy_url`, including the port number
//! and a random nonce.
//!
//! The `Proxy` server returns an OAuth 2.0 authz request URL.
//!
//! 2. The `User` visits this URL (the `Server`) ito authorize the request.
//!    This includes a URL redirection back to the `Proxy`.
//!    
//! 3. The redirected request should contain the authz code
//!    from the OAuth 2.0 `Server`.
//!
//! 4. The `Proxy` exchanges the authz code for an access token.
//!    This token can be used to access `Server` resources
//!    (depending on the scopes requested).
//!
//! 5. The `Proxy` determines the identity of the `User`
//!    by using this access.
//!	   The `Proxy` responds to the `User` request by serving an
//!    HTTP page (a welcome page) which should include a request
//!    to the local HTTP server with the final session token.
//!
//! 6. When the `User` browser makes a request to the local
//!    HTTP server being run by the `Client`, the session secret
//!    is captured, and the `Client` can continue in authenticated mode.
//!
//! ### Diagram
//! ```
//!                        4. Exchange authz code from (3)
//!                        Use token to verify identity.
//!                        to get an access_token.
//!                        (e.g. GET /api/user?token=123)
//!               +------------------------------------------+
//!               ^                                          |
//!       +-------+--------+3. GET /oauth-cli/finish +-------+------+
//!       | OAuth 2.0      |   Response:             |  OAuth 2.0   |
//!       | Authz provider |   welcome page          |  Client      |
//!       | ("Server")     |      +-----------------^+  ("Proxy")   |
//!       +-------+--------+      |  5. Respond with +-------+------+
//!               ^               |     session token        ^
//!               |               |                          |
//!               +------+        |       +------------------+
//! 2. In browser:       |        |       |       1. Get authz URL
//! Visit AuthURL        |        |       |       POST /oauth-cli/start
//!                      +--------+-------+-+
//! Response:            | CLI Application  |       Response: AuthURL
//! redirect-to          | ("Client"/"User")|
//! GET /oauth-cli/finish+---+----+---------+
//! ?code=...&port=...       |    ^
//!                          |    |
//!                          +----+
//!                     6. GET localhost:<port>/
//!                     With some query values
//!                     e.g. new_secret=123
//! 
//! 
//! ```

#![feature(uniform_paths)]

pub mod client;
pub mod proxy;
pub mod server;
mod msgs;
mod util;

use url::Url;

pub(crate) fn get_redirect_page(redirect_url: &Url, welcome_redirect: &Url) -> String {
    let html = include_str!("redirect_template.html");
    let mut combined_url = redirect_url.clone();
    combined_url.query_pairs_mut().append_pair("welcome_redirect", &welcome_redirect.to_string());
    let html = html.replace("{{redirect_url}}", &redirect_url.to_string());
    let html = html.replace("{{welcome_url}}", &welcome_redirect.to_string());
    let html = html.replace("{{combined_url}}", &combined_url.to_string());

    html
}