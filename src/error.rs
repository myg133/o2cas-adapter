use std::fmt;
use std::error::Error as StdError;
use axum::response::{IntoResponse, Response};
use http::StatusCode;

#[derive(Debug)]
pub enum AppError {
    ConfigLoadError(String),
    OAuth2Error(String),
    CASError(String),
    JWTError(String),
    Unauthorized(String),
    CasValidationFailed(String),
    XmlParseError(String),
    UrlEncodingError(String),
    ChronoError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AppError::ConfigLoadError(ref e) => write!(f, "配置加载错误: {}", e),
            AppError::OAuth2Error(ref e) => write!(f, "OAuth2错误: {}", e),
            AppError::CASError(ref e) => write!(f, "CAS错误: {}", e),
            AppError::JWTError(ref e) => write!(f, "JWT错误: {}", e),
            AppError::Unauthorized(ref e) => write!(f, "未授权: {}", e),
            AppError::CasValidationFailed(ref e) => write!(f, "CAS验证失败: {}", e),
            AppError::XmlParseError(ref e) => write!(f, "XML解析错误: {}", e),
            AppError::UrlEncodingError(ref e) => write!(f, "URL编码错误: {}", e),
            AppError::ChronoError(ref e) => write!(f, "时间计算错误: {}", e),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::ConfigLoadError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::OAuth2Error(_) => StatusCode::BAD_GATEWAY,
            AppError::CASError(_) => StatusCode::BAD_GATEWAY,
            AppError::JWTError(_) => StatusCode::UNAUTHORIZED,
            AppError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AppError::CasValidationFailed(_) => StatusCode::BAD_GATEWAY,
            AppError::XmlParseError(_) => StatusCode::BAD_REQUEST,
            AppError::UrlEncodingError(_) => StatusCode::BAD_REQUEST,
            AppError::ChronoError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, self.to_string()).into_response()
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::ConfigLoadError(err.to_string())
    }
}

impl From<toml::de::Error> for AppError {
    fn from(err: toml::de::Error) -> Self {
        AppError::ConfigLoadError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AppError::JWTError(err.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        AppError::CASError(err.to_string())
    }
}

impl From<roxmltree::Error> for AppError {
    fn from(err: roxmltree::Error) -> Self {
        AppError::XmlParseError(err.to_string())
    }
}

impl From<Box<dyn StdError>> for AppError {
    fn from(err: Box<dyn StdError>) -> Self {
        AppError::ConfigLoadError(err.to_string())
    }
}

impl From<String> for AppError {
    fn from(err: String) -> Self {
        AppError::UrlEncodingError(err)
    }
}

impl From<chrono::OutOfRangeError> for AppError {
    fn from(err: chrono::OutOfRangeError) -> Self {
        AppError::ChronoError(err.to_string())
    }
}
