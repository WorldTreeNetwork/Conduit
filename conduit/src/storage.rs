//! Storage abstraction.
//!
//! `conduit` doesn't bind to a particular database. Implement the
//! [`Storage`] trait on top of whatever you like — sqlite, rocksdb,
//! postgres, an in-memory map for tests — and pass it in at startup.

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::event::Event;
use crate::Result;

#[async_trait]
pub trait Storage: Send + Sync + 'static {
    async fn get_event(&self, event_id: &str) -> Result<Option<Event>>;
    async fn put_event(&self, event: &Event) -> Result<()>;
    async fn room_events(&self, room_id: &str) -> Result<Vec<Event>>;
}

/// An in-memory [`Storage`] for tests and demos. Not durable.
#[derive(Default)]
pub struct MemoryStorage {
    inner: RwLock<MemoryInner>,
}

#[derive(Default)]
struct MemoryInner {
    events: HashMap<String, Event>,
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn get_event(&self, event_id: &str) -> Result<Option<Event>> {
        Ok(self.inner.read().await.events.get(event_id).cloned())
    }

    async fn put_event(&self, event: &Event) -> Result<()> {
        self.inner
            .write()
            .await
            .events
            .insert(event.event_id.clone(), event.clone());
        Ok(())
    }

    async fn room_events(&self, room_id: &str) -> Result<Vec<Event>> {
        Ok(self
            .inner
            .read()
            .await
            .events
            .values()
            .filter(|e| e.room_id == room_id)
            .cloned()
            .collect())
    }
}
