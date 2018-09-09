//! Paramterization of the OAuth 2.0 providers

use serde_derive::Deserialize;
use oauth2::prelude::*;
use oauth2::{AuthUrl, TokenUrl};
use url::Url;

use crate::util::*;

/// The `Provider` enum captures the different OAuth 2.0
/// authentication providers.
#[derive(Clone, Debug, Deserialize)]
pub enum Provider {
    Github,
    Custom {
        /// URL to authorize the OAuth2.0 request
        #[serde(with="serde_newtype_url")]
        auth_url: AuthUrl,

        /// URL to recover the OAuth2.0 token given a successful
        /// authorization.
        #[serde(with="serde_newtype_url")]
        token_url: TokenUrl,
    }
}

impl Provider {
    pub fn into_urls(self) -> (AuthUrl, TokenUrl) {
        match self {
            Provider::Github => (
                AuthUrl::new(Url::parse("https://github.com/login/oauth/authorize").unwrap()),
                TokenUrl::new(Url::parse("https://github.com/login/oauth/access_token").unwrap())
            ),
            Provider::Custom { auth_url, token_url } => (auth_url, token_url),
        }
    }
}
