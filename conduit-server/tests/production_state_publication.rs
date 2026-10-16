//! The event row and its current-state pointer commit together.
mod common;

use common::production::Server;
use reqwest::Method;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

#[tokio::test]
async fn event_is_not_visible_while_its_current_state_update_is_blocked() {
    let server = Server::new().await;
    let (alice, _, room, _) = server.chat_pair().await;
    let token = alice["access_token"].as_str().unwrap().to_owned();
    let path = format!("/_matrix/client/v3/rooms/{room}/state/m.room.name");
    server
        .request(Method::PUT, &path, Some(&token), Some(json!({"name": "Before publication"})), 200)
        .await;
    let pool = PgPoolOptions::new().max_connections(2).connect(&server.database_url).await.unwrap();
    let mut hold = pool.begin().await.unwrap();
    sqlx::query(
        "SELECT event_id FROM room_current_state WHERE room_id=$1 AND type='m.room.name' AND state_key='' FOR UPDATE",
    )
    .bind(&room)
    .fetch_one(&mut *hold)
    .await
    .unwrap();
    let http = server.http.clone();
    let url = format!("{}{path}", server.base_url);
    let writing = tokio::spawn(async move {
        http.put(url)
            .bearer_auth(token)
            .json(&json!({"name": "After publication"}))
            .send()
            .await
            .unwrap()
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE '%room_current_state%' AND pid<>pg_backend_pid())",
        )
        .bind(&server.database_name)
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiting {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "writer never reached the held state row");
        tokio::task::yield_now().await;
    }
    let visible: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM events WHERE room_id=$1 AND type='m.room.name' AND content->>'name'='After publication')",
    )
    .bind(&room)
    .fetch_one(&pool)
    .await
    .unwrap();
    hold.commit().await.unwrap();
    let response = writing.await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(!visible, "event and resolved current state must become visible in the same commit");
    pool.close().await;
}
