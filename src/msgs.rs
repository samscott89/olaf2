use oauth2::{AuthorizationCode, CsrfToken};
use serde::{de::DeserializeOwned, Serialize};
use serde_derive::{Deserialize, Serialize};
use url::Url;
use url_serde::Serde;

use std::fmt::Debug;

use crate::util::*;

/// Parameters sent from client -> proxy server 
/// on initial generate OAuth2 query.
#[derive(Debug, Deserialize, Serialize)]
pub struct GenParams {
    #[serde(with="serde_secret_newtype", rename="state")]
    pub csrf_token: CsrfToken,
    pub client_port: u16,
}

/// Parameters sent from OAuth2 server back
/// to the proxy server after successful
/// authorization takes place
#[derive(Debug, Deserialize, Serialize)]
pub struct FinParams {
    #[serde(with="serde_secret_newtype", rename="state")]
    pub csrf_token: CsrfToken,
    pub client_port: u16,
	#[serde(with="serde_secret_newtype")]
	pub code: AuthorizationCode,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FinResponse<R>
    // where R: Debug + DeserializeOwned + Serialize
{
	#[serde(with="serde_secret_newtype", rename="state")]
	pub csrf_token: CsrfToken,
	pub response: R,
    pub welcome_redirect: Option<Serde<Url>>,
}