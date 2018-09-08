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
//! ## Usage
//!
//!

#![feature(uniform_paths)]

// mod client;
mod server;
mod msgs;
mod util;

use msgs::*;
use util::*;

