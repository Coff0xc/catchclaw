use std::sync::OnceLock;

use super::{PlatformProfile, TargetPlatform};
use super::profiles::*;

static REGISTRY: OnceLock<PlatformRegistry> = OnceLock::new();

pub struct PlatformRegistry {
    profiles: Vec<Box<dyn PlatformProfile>>,
}

impl PlatformRegistry {
    pub fn global() -> &'static Self {
        REGISTRY.get_or_init(|| Self {
            profiles: vec![
                Box::new(OpenClawProfile),
                Box::new(LibreChatProfile),
                Box::new(LobeChatProfile),
                Box::new(DifyProfile),
                Box::new(FastGPTProfile),
                Box::new(NextChatProfile),
                Box::new(AnythingLLMProfile),
                Box::new(FlowiseProfile),
                Box::new(RagFlowProfile),
            ],
        })
    }

    pub fn get(&self, platform: TargetPlatform) -> Option<&dyn PlatformProfile> {
        self.profiles.iter()
            .find(|p| p.platform() == platform)
            .map(|p| p.as_ref())
    }

    pub fn all(&self) -> &[Box<dyn PlatformProfile>] {
        &self.profiles
    }
}
