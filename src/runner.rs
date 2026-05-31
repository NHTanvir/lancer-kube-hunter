use std::collections::VecDeque;
use std::sync::Arc;
use tokio::task::JoinSet;

use crate::hunter::Hunter;
use crate::types::{Event, Finding, HunterCtx, Mode, Output};

pub struct Runner {
    hunters: Vec<Arc<dyn Hunter>>,
    ctx:     Arc<HunterCtx>,
}

impl Runner {
    pub fn new(
        mode:           Mode,
        hunters:        Vec<Arc<dyn Hunter>>,
        port_timeout:   std::time::Duration,
        custom_ports:   Option<Vec<u16>>,
        sa_token:       Option<String>,
        interface_mode: bool,
    ) -> anyhow::Result<Self> {
        let ctx = Arc::new(
            HunterCtx::new(mode, port_timeout, custom_ports)?
                .with_options(sa_token, interface_mode),
        );
        Ok(Self { hunters, ctx })
    }

    pub async fn run(&self, initial_events: Vec<Event>) -> Vec<Finding> {
        let mut queue: VecDeque<Event> = initial_events.into();
        let mut findings: Vec<Finding> = Vec::new();

        while let Some(event) = queue.pop_front() {
            let event_arc = Arc::new(event);
            let mut set: JoinSet<Vec<Output>> = JoinSet::new();

            for hunter in &self.hunters {
                // Skip active hunters in passive mode.
                if hunter.mode() == Mode::Active && self.ctx.mode == Mode::Passive {
                    continue;
                }
                if hunter.subscribes_to() != event_arc.kind() {
                    continue;
                }
                if !hunter.predicate(&event_arc) {
                    continue;
                }

                let h   = Arc::clone(hunter);
                let ctx = Arc::clone(&self.ctx);
                let ev  = Arc::clone(&event_arc);
                set.spawn(async move { h.execute(ctx, ev).await });
            }

            while let Some(res) = set.join_next().await {
                match res {
                    Ok(outputs) => {
                        for out in outputs {
                            match out {
                                Output::Finding(f) => findings.push(f),
                                Output::Event(e)   => queue.push_back(e),
                            }
                        }
                    }
                    Err(e) => tracing::warn!("Hunter task panicked: {e}"),
                }
            }
        }

        findings
    }
}
