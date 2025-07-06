use crate::error::{ApiError, Result};
use crate::state::{AppState, ProfileStats};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use huginn_core::TrafficProfile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Response for the health check endpoint
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Response for the profiles list endpoint
#[derive(Serialize)]
pub struct ProfilesResponse {
    pub profiles: HashMap<String, TrafficProfile>,
    pub count: usize,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Query parameters for filtering profiles
#[derive(Deserialize)]
pub struct ProfileQuery {
    /// Filter by minimum completeness (0.0-1.0)
    pub min_completeness: Option<f64>,
    /// Filter by having TCP data
    pub has_tcp: Option<bool>,
    /// Filter by having HTTP data
    pub has_http: Option<bool>,
    /// Filter by having TLS data
    pub has_tls: Option<bool>,
    /// Limit number of results
    pub limit: Option<usize>,
}

/// Health check endpoint
/// GET /health
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: crate::VERSION.to_string(),
        timestamp: chrono::Utc::now(),
    })
}

/// Get all traffic profiles
/// GET /api/profiles
pub async fn get_profiles(
    State(state): State<AppState>,
    Query(query): Query<ProfileQuery>,
) -> Result<Json<ProfilesResponse>> {
    let all_profiles = state.get_profiles();

    // Apply filters
    let mut filtered_profiles = HashMap::new();

    for (key, profile) in all_profiles.iter() {
        // Apply completeness filter
        if let Some(min_completeness) = query.min_completeness {
            if profile.metadata.completeness < min_completeness {
                continue;
            }
        }

        // Apply TCP filter
        if let Some(has_tcp) = query.has_tcp {
            if has_tcp && profile.tcp.is_none() {
                continue;
            }
            if !has_tcp && profile.tcp.is_some() {
                continue;
            }
        }

        // Apply HTTP filter
        if let Some(has_http) = query.has_http {
            if has_http && profile.http.is_none() {
                continue;
            }
            if !has_http && profile.http.is_some() {
                continue;
            }
        }

        // Apply TLS filter
        if let Some(has_tls) = query.has_tls {
            if has_tls && profile.tls.is_none() {
                continue;
            }
            if !has_tls && profile.tls.is_some() {
                continue;
            }
        }

        filtered_profiles.insert(key.clone(), profile.clone());

        // Apply limit
        if let Some(limit) = query.limit {
            if filtered_profiles.len() >= limit {
                break;
            }
        }
    }

    Ok(Json(ProfilesResponse {
        count: filtered_profiles.len(),
        profiles: filtered_profiles,
        timestamp: chrono::Utc::now(),
    }))
}

/// Get a specific traffic profile by key
/// GET /api/profiles/{key}
pub async fn get_profile(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<Json<TrafficProfile>> {
    match state.get_profile(&key) {
        Some(profile) => Ok(Json(profile)),
        None => Err(ApiError::not_found(format!("Profile not found: {}", key))),
    }
}

/// Delete a specific traffic profile
/// DELETE /api/profiles/{key}
pub async fn delete_profile(
    State(state): State<AppState>,
    Path(key): Path<String>,
) -> Result<StatusCode> {
    match state.remove_profile(&key) {
        Some(_) => Ok(StatusCode::NO_CONTENT),
        None => Err(ApiError::not_found(format!("Profile not found: {}", key))),
    }
}

/// Clear all traffic profiles
/// DELETE /api/profiles
pub async fn clear_profiles(State(state): State<AppState>) -> StatusCode {
    state.clear_profiles();
    StatusCode::NO_CONTENT
}

/// Get statistics about traffic profiles
/// GET /api/stats
pub async fn get_stats(State(state): State<AppState>) -> Json<ProfileStats> {
    Json(state.get_stats())
}

/// Response for profile search
#[derive(Serialize)]
pub struct SearchResponse {
    pub results: Vec<SearchResult>,
    pub count: usize,
    pub query: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Individual search result
#[derive(Serialize)]
pub struct SearchResult {
    pub key: String,
    pub profile: TrafficProfile,
    pub relevance: f64,
}

/// Query parameters for searching profiles
#[derive(Deserialize)]
pub struct SearchQuery {
    /// Search query string
    pub q: String,
    /// Maximum number of results
    pub limit: Option<usize>,
}

/// Search traffic profiles
/// GET /api/search
pub async fn search_profiles(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResponse>> {
    let all_profiles = state.get_profiles();
    let search_term = query.q.to_lowercase();
    let limit = query.limit.unwrap_or(50);

    let mut results = Vec::new();

    for (key, profile) in all_profiles.iter() {
        let mut relevance = 0.0;
        let mut matches = 0;

        // Search in IP address
        if profile.ip.to_string().contains(&search_term) {
            relevance += 1.0;
            matches += 1;
        }

        // Search in TCP OS detection
        if let Some(tcp) = &profile.tcp {
            if tcp.os.to_lowercase().contains(&search_term) {
                relevance += 0.8;
                matches += 1;
            }
        }

        // Search in HTTP browser detection
        if let Some(http) = &profile.http {
            if http.browser.to_lowercase().contains(&search_term) {
                relevance += 0.8;
                matches += 1;
            }
        }

        // Search in TLS JA4 fingerprint
        if let Some(tls) = &profile.tls {
            if tls.ja4.to_lowercase().contains(&search_term) {
                relevance += 0.6;
                matches += 1;
            }
        }

        // Only include results with matches
        if matches > 0 {
            results.push(SearchResult {
                key: key.clone(),
                profile: profile.clone(),
                relevance: relevance / matches as f64,
            });
        }

        if results.len() >= limit {
            break;
        }
    }

    // Sort by relevance (highest first)
    results.sort_by(|a, b| b.relevance.partial_cmp(&a.relevance).unwrap());

    Ok(Json(SearchResponse {
        count: results.len(),
        results,
        query: query.q,
        timestamp: chrono::Utc::now(),
    }))
}

/// Response for API information
#[derive(Serialize)]
pub struct ApiInfoResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub endpoints: Vec<EndpointInfo>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Information about an API endpoint
#[derive(Serialize)]
pub struct EndpointInfo {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Get API information and available endpoints
/// GET /api
pub async fn api_info() -> Json<ApiInfoResponse> {
    Json(ApiInfoResponse {
        name: "Huginn API".to_string(),
        version: crate::VERSION.to_string(),
        description: "REST API for Huginn network traffic profiler".to_string(),
        endpoints: vec![
            EndpointInfo {
                method: "GET".to_string(),
                path: "/health".to_string(),
                description: "Health check endpoint".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api".to_string(),
                description: "API information and endpoints".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/profiles".to_string(),
                description: "Get all traffic profiles with optional filtering".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/profiles/{key}".to_string(),
                description: "Get a specific traffic profile".to_string(),
            },
            EndpointInfo {
                method: "DELETE".to_string(),
                path: "/api/profiles/{key}".to_string(),
                description: "Delete a specific traffic profile".to_string(),
            },
            EndpointInfo {
                method: "DELETE".to_string(),
                path: "/api/profiles".to_string(),
                description: "Clear all traffic profiles".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/stats".to_string(),
                description: "Get statistics about traffic profiles".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/api/search".to_string(),
                description: "Search traffic profiles".to_string(),
            },
            EndpointInfo {
                method: "GET".to_string(),
                path: "/ws".to_string(),
                description: "WebSocket endpoint for real-time updates".to_string(),
            },
        ],
        timestamp: chrono::Utc::now(),
    })
}
