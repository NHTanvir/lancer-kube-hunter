use std::sync::Arc;
use async_trait::async_trait;
use crate::types::{Event, EventKind, Mode, Output, HunterCtx};

#[async_trait]
pub trait Hunter: Send + Sync {
    #[allow(dead_code)]
    fn name(&self)          -> &'static str;
    #[allow(dead_code)]
    fn description(&self)   -> &'static str { "" }
    fn mode(&self)          -> Mode;
    fn subscribes_to(&self) -> EventKind;
    fn predicate(&self, _event: &Event) -> bool { true }
    async fn execute(&self, ctx: Arc<HunterCtx>, event: Arc<Event>) -> Vec<Output>;
}
