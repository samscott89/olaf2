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



use oauth2::basic::BasicClient;
use oauth2::prelude::*;
use oauth2::{AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
             TokenUrl};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use url::Url;

mod server;

fn main() {
    simulate_client("127.0.0.1:8080".parse().unwrap());
}



pub fn simulate_client(addr: SocketAddr) {
    let authorize_url = reqwest::get(&format!("{}/oauth-cli", addr)).unwrap().text().unwrap();

    if open::that(authorize_url.to_string()).is_err() {
        println!(
            "Open this URL in your browser:\n{}\n",
            authorize_url.to_string()
        );
    }
    // A very naive implementation of the redirect server.
    let listener = TcpListener::bind("127.0.0.1:31415").unwrap();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let code;
            let state;
            {
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).unwrap();

                let redirect_url = request_line.split_whitespace().nth(1).unwrap();
                let url = Url::parse(&("http://localhost".to_string() + redirect_url)).unwrap();

                let code_pair = url.query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "code"
                    })
                    .unwrap();

                let (_, value) = code_pair;
                code = AuthorizationCode::new(value.into_owned());

                let state_pair = url.query_pairs()
                    .find(|pair| {
                        let &(ref key, _) = pair;
                        key == "state"
                    })
                    .unwrap();

                let (_, value) = state_pair;
                state = CsrfToken::new(value.into_owned());
            }

            let message = "";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                message.len(),
                message
            );
            stream.write_all(response.as_bytes()).unwrap();

            println!("Github returned the following code:\n{}\n", code.secret());
            // println!(
            //     "Github returned the following state:\n{} (expected `{}`)\n",
            //     state.secret(),
            //     csrf_state.secret()
            // );

            // // Exchange the code with a token.
            // let token_res = client.exchange_code(code);

            // println!("Github returned the following token:\n{:?}\n", token_res);

            // if let Ok(token) = token_res {
            //     // NB: Github returns a single comma-separated "scope" parameter instead of multiple
            //     // space-separated scopes. Github-specific clients can parse this scope into
            //     // multiple scopes by splitting at the commas. Note that it's not safe for the
            //     // library to do this by default because RFC 6749 allows scopes to contain commas.
            //     let scopes = if let Some(scopes_vec) = token.scopes() {
            //         scopes_vec
            //             .iter()
            //             .map(|comma_separated| comma_separated.split(","))
            //             .flat_map(|inner_scopes| inner_scopes)
            //             .collect::<Vec<_>>()
            //     } else {
            //         Vec::new()
            //     };
            //     println!("Github returned the following scopes:\n{:?}\n", scopes);
            // }

            // The server will terminate itself after collecting the first code.
            break;
        }
    }
}
