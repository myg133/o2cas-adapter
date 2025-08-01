use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Json, Redirect}, Form,
};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation};
use chrono::{Utc, Duration};
use std::{collections::HashMap, sync::Arc};
use crate::{error::AppError, config::Config};
use tracing::{event, Level};
use base64::{engine::general_purpose, Engine};

#[derive(Debug, Deserialize)]
pub struct OAuth2LoginParams {
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CasCallbackParams {
    ticket: String,
    service: String,
    client_id: String,
    state: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    sub: String,  // username
    client_id: String,
    ticket: String,
    exp: i64,  // expiry timestamp
}

pub async fn oauth2_login(
    State(config): State<Arc<Config>>,
    Query(params): Query<OAuth2LoginParams>,
) -> Result<impl IntoResponse, AppError> {
    event!(Level::INFO,"OAuth2 login request - client_id: {}, redirect_uri: {}", params.client_id, params.redirect_uri);
    event!(Level::DEBUG,"OAuth2 login - params {:?}", params);
    // 构建CAS登录URL
    let encoded_client_id = urlencoding::encode(&params.client_id).into_owned();
    let encoded_redirect_uri = urlencoding::encode(&params.redirect_uri).into_owned();
    let encoded_state = params.state.as_ref().map(|s| urlencoding::encode(s).into_owned());
    let encoded_scope = params.scope.as_ref().map(|s| urlencoding::encode(s).into_owned());

    let cas_url = format!(
        "{}?{}={}/cas/callback&client_id={}&redirect_uri={}{}{}",
        config.cas.login_url,
        config.cas.service_param,
        config.server.endpoint,
        encoded_client_id,
        encoded_redirect_uri,
        encoded_state.as_ref().map(|s| format!("&state={}", s)).unwrap_or_default(),
        encoded_scope.as_ref().map(|s| format!("&scope={}", s)).unwrap_or_default()
    );
    event!(Level::DEBUG,"OAuth2 login - cas_url {}", cas_url);

    Ok(Redirect::to(&cas_url))
}

pub async fn cas_callback(
    State(config): State<Arc<Config>>,
    Query(params): Query<CasCallbackParams>,
) -> Result<impl IntoResponse, AppError> {
    event!(Level::INFO,"CAS callback received - ticket: {}, service: {}, client_id: {}", 
        params.ticket, params.service, params.client_id);
    event!(Level::DEBUG,"CAS callback - params {:?}", params);
    // 将ticket和service编码为base64作为code
    let code = general_purpose::STANDARD.encode(format!("{}|{}", params.ticket, params.service));
    
    // 生成JWT
    let exp = (Utc::now() + Duration::minutes(10)).timestamp();
    let claims = TokenClaims {
        sub: "".to_string(), // 用户名留空，在userinfo时获取
        client_id: params.client_id,
        ticket: code, // 存储base64编码的ticket:service
        exp,
    };
    
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt.secret.as_ref()),
    )?;
    
    // 重定向回OAuth2回调地址
    let encoded_token = urlencoding::encode(&token).into_owned();
    let encoded_state = params.state.as_ref().map(|s| urlencoding::encode(s).into_owned());
    
    let redirect_url = format!(
        "{}?code={}&state={}",
        config.oauth2.redirect_uri.clone(),
        encoded_token,
        encoded_state.as_ref().map(|s| s.as_str()).unwrap_or_default()
    );
    event!(Level::DEBUG,"CAS callback - redirect_url {}", redirect_url);
    
    Ok(Redirect::to(&redirect_url))
}

pub async fn exchange_token(
    State(_config): State<Arc<Config>>,
    Form(payload): Form<TokenRequest>,
) -> Result<impl IntoResponse, AppError> {
    event!(Level::INFO,"Token exchange request - client_id: {}, redirect_uri: {}", payload.client_id, payload.redirect_uri);
    let config = Config::load()?;
    
    // 验证code (实际上是JWT)
    let token_data = decode::<TokenClaims>(
        &payload.code,
        &DecodingKey::from_secret(config.jwt.secret.as_ref()),
        &Validation::default(),
    )?;
    
    // 返回token响应
    Ok(Json(TokenResponse {
        access_token: payload.code, // 直接返回JWT作为access_token
        token_type: "Bearer".to_string(),
        expires_in: (token_data.claims.exp - Utc::now().timestamp()).max(0),
        refresh_token: None,
    }))
}

pub async fn get_user_info(
    State(config): State<Arc<Config>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    event!(Level::INFO,"User info request received");
    event!(Level::DEBUG,"User info - headers {:?}", headers);
    let auth_header = headers.get("Authorization")
        .and_then(|h| h.to_str().ok());
    let config = Config::load()?;
    
    // 验证Authorization头
    let token = auth_header
        .ok_or_else(|| {
            event!(Level::ERROR,"Missing authorization header");
            AppError::Unauthorized("Missing authorization header".to_string())
        })?
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            event!(Level::ERROR,"Invalid token format");
            AppError::Unauthorized("Invalid token format".to_string())
        })?;
    
    // 解析JWT
    let token_data = decode::<TokenClaims>(
        token,
        &DecodingKey::from_secret(config.jwt.secret.as_ref()),
        &Validation::default(),
    ).map_err(|e| {
        event!(Level::ERROR,"JWT decode failed: {}", e);
        e
    })?;
    event!(Level::INFO,"JWT decoded successfully - {:?}", token_data.claims);
    
    // 从JWT中获取ticket和service
    let ticket_service = general_purpose::STANDARD.decode(&token_data.claims.ticket)
        .map_err(|_| AppError::CasValidationFailed("Invalid ticket format".to_string()))?;
    let ticket_service = String::from_utf8(ticket_service)
        .map_err(|_| AppError::CasValidationFailed("Invalid ticket format".to_string()))?;
    
    let parts: Vec<&str> = ticket_service.split('|').collect();
    if parts.len() != 2 {
        return Err(AppError::CasValidationFailed("Invalid ticket format".to_string()));
    }
    let ticket = parts[0];
    let service = parts[1];
    
    // 验证CAS票据
    let encoded_ticket = urlencoding::encode(ticket).into_owned();
    let encoded_service = urlencoding::encode(service).into_owned();
    
    let validation_url = format!(
        "{}?ticket={}&{}={}",
        config.cas.validate_url,
        encoded_ticket,
        config.cas.service_param,
        encoded_service
    );
    event!(Level::DEBUG,"ticket url - {:?}", validation_url);
    
    // 调用CAS验证接口获取用户信息
    let client = reqwest::Client::new();
    let response = client.get(&validation_url)
        .send()
        .await
        .map_err(|e| {
            event!(Level::ERROR,"CAS validation request failed: {}", e);
            AppError::CasValidationFailed(e.to_string())
        })?;
    event!(Level::INFO,"CAS validation response status: {}", response.status());
    
    if !response.status().is_success() {
        return Err(AppError::CasValidationFailed(
            format!("CAS validation failed with status: {}", response.status())
        ));
    }
    
    let body = response.text().await.map_err(|e| {
        event!(Level::ERROR,"Failed to read CAS validation response: {}", e);
        AppError::CasValidationFailed(e.to_string())
    })?;
    event!(Level::DEBUG,"CAS validation response body: {}", body);
    // 获取字段映射规则
    let field_mapping = config.field_mapping;
    // 解析CAS响应获取用户详细信息
    let cas_fields = parse_cas_response(&body).map_err(|e|{
        event!(Level::ERROR,"Failed to parse CAS response: {}", e);
        e 
    })?;
    event!(Level::DEBUG,"CAS validation fields: {:?}", cas_fields);

    // 应用映射规则构建响应
    let mut user_info = serde_json::Map::new();
    for (response_key, cas_key) in field_mapping {
        if let Some(value) = cas_fields.get(&cas_key) {
            user_info.insert(response_key.clone(), serde_json::Value::String(value.clone()));
        }
    }

    event!(Level::DEBUG,"CAS validation user info: {:?}", user_info);
    
    // 返回用户信息
    Ok(Json(serde_json::Value::Object(user_info)))
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    code: String,
    grant_type: String,
    redirect_uri: String,
    client_id: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
    refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    sub: String,
    name: String,
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
}

/// 解析CAS验证响应获取用户信息
fn parse_cas_response(body: &str) -> Result<HashMap<String, String>, AppError> {
    // 简单示例：从XML响应中提取用户信息
    // 实际应根据CAS服务器的响应格式实现
    let doc = roxmltree::Document::parse(body)
        .map_err(|e| {
            event!(Level::ERROR,"{}", e);
            AppError::CasValidationFailed(e.to_string())
        }
        )?;
    // 添加base64解码辅助函数
    let decode_base64_if_needed = |s: Option<String>| {
        let res = if let Some(s) = s {
            if s.starts_with("base64:") {
                general_purpose::STANDARD.decode(&s[7..])
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or(s.to_string())
            } else {
                s.to_string()
            }
        } else {
            String::new()
        };
        res
    };

    
    // 获取CAS命名空间URI（可能出现在根节点）
    let cas_ns = doc.root_element()
        .namespaces()
        .find(|ns| ns.name().unwrap_or("") == "cas")
        .map(|ns| ns.uri())
        .unwrap_or("http://www.yale.edu/tp/cas");

    let mut cas_fields = HashMap::new();
    if let Some(success_node) = doc.descendants().find(|n| n.tag_name().namespace() == Some(cas_ns) && n.tag_name().name() == "authenticationSuccess") {
        for child in success_node.descendants() {
            if child.is_element() {
                let field_name = child.tag_name().name();
                let field_value = decode_base64_if_needed(Some(child.text().unwrap_or_default().to_string()));
                cas_fields.insert(field_name.to_string(), field_value);
            }
        }
    }
    Ok(cas_fields)
}
