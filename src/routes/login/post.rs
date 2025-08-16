use actix_web::{
    HttpResponse, ResponseError,
    cookie::Cookie,
    error::InternalError,
    http::{StatusCode, header::LOCATION},
    web,
};
use secrecy::SecretString;
use serde::Deserialize;
use sqlx::PgPool;

use crate::{
    authentication::{AuthError, Credentials, validate_credentials},
    routes::error_chain_fmt,
};

#[derive(Deserialize)]
pub struct FormData {
    username: String,
    password: SecretString,
}

#[tracing::instrument(
    skip(form, pool),
    fields(username=tracing::field::Empty,user_id=tracing::field::Empty))
]
pub async fn login(
    form: web::Form<FormData>,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, InternalError<LoginError>> {
    let credentials = Credentials {
        username: form.0.username,
        password: form.0.password,
    };
    tracing::Span::current().record("username", tracing::field::display(&credentials.username));

    match validate_credentials(credentials, &pool).await {
        Ok(user_id) => {
            tracing::Span::current().record("user_id", tracing::field::display(&user_id));
            Ok(HttpResponse::SeeOther()
                .insert_header((LOCATION, "/"))
                .finish())
        }
        Err(e) => {
            let e = match e {
                AuthError::InvalidCredentials(_) => LoginError::AuthError(e.into()),
                AuthError::UnExpectedError(_) => LoginError::UnExpectedError(e.into()),
            };

            let response = HttpResponse::SeeOther()
                .insert_header((LOCATION, "/login".to_string()))
                .cookie(Cookie::new("_flash", e.to_string()))
                .finish();
            Err(InternalError::from_response(e, response))
        }
    }
}

#[derive(thiserror::Error)]
pub enum LoginError {
    #[error("Authentication failed")]
    AuthError(#[source] anyhow::Error),
    #[error("Something went wrong")]
    UnExpectedError(#[from] anyhow::Error),
}

impl std::fmt::Debug for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl ResponseError for LoginError {
    fn status_code(&self) -> StatusCode {
        StatusCode::SEE_OTHER
    }
}
