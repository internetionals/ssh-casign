use serde::Serialize;

use crate::error::{Report, Result};

pub(crate) struct AuthToken {
    access_token: String,
}

pub(crate) struct AuthClient {
    http: reqwest::Client,
    oidc_url: String,
    token_endpoint: String,
    token: Option<AuthToken>,
}

#[derive(Serialize)]
struct OidcAuthRequest {
    grant_type: String,
    code: String,
    client_id: String,
    client_secret: String,
}

impl AuthClient {
    pub(crate) async fn new(oidc_url: String) -> Result<Self> {
        let http = reqwest::Client::new();
        let oidc_config: serde_json::Value = http.get(oidc_url.clone() + "/.well-known/openid-configuration").send().await?.error_for_status()?.json().await?;
        let token_endpoint = oidc_config.get("token_endpoint").ok_or(Report::msg("OpenID Connect configuration without a 'token_endpoint'"))?.as_str().ok_or(Report::msg("OpenID Connect configuration 'token_endpoint' not a string"))?.to_string();

        Ok(Self {
            http,
            oidc_url,
            token_endpoint,
            token: None,
        })
    }

    // pub(crate) async fn auth_token(&self) -> Result<String> {
    //     let res = self.http.post(self.token_endpoint).form(&OidcAuthRequest{
    //         grant_type: "client_credentials".to_string(),
    //         code: "foobar".to_string(),
    //         client_id: self.client_id,
    //         client_secret: self.client_secret,
    //     }).send().await?;
    //     if !res.status().is_success() {
    //         panic!("Foo");
    //     }
    //     let body = res.bytes().await?;
    //     if !body.is_ascii() {
    //         panic!("AARGH");
    //     }
    //     Ok(str::from_utf8(body.iter().as_slice())?.to_owned())
    // }
}

// RESPONSE="$(curl -d grant_type=client_credentials -d code="${DUMMY_USER:-user1}"  -d client_id=foo -d client_secret=bar http://localhost:8080/ssh-casign/token)"
// echo "$RESPONSE" | jq -r .access_token

