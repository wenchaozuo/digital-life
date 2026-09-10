use std::{collections::BTreeMap, fmt};

pub(crate) const MAX_CAPABILITY_ID_LENGTH: usize = 128;
const MAX_DISPLAY_NAME_LENGTH: usize = 256;
pub(crate) const PRODUCTION_GIT_STATUS_CAPABILITY_ID: &str = "vita.process.workspace.git_status";
pub(crate) const PRODUCTION_GIT_STATUS_PROFILE_ID: &str = "d29h7c.git.status.v1";
pub(crate) const PRODUCTION_GIT_STATUS_TOOL_NAME: &str = "vita_workspace_git_status";

/// A capability identity is an opaque, exact, lower-case ASCII identifier.
/// No normalization, aliasing, or case folding is performed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CapabilityId(String);

impl CapabilityId {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self, CapabilityIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CapabilityIdError::Empty);
        }
        if value.len() > MAX_CAPABILITY_ID_LENGTH {
            return Err(CapabilityIdError::TooLong);
        }
        if value
            .bytes()
            .any(|byte| !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        {
            return Err(CapabilityIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CapabilityId {
    type Error = CapabilityIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for CapabilityId {
    type Error = CapabilityIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityIdError {
    Empty,
    TooLong,
    InvalidCharacter,
}

impl fmt::Display for CapabilityIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "capability id must not be empty",
            Self::TooLong => "capability id is too long",
            Self::InvalidCharacter => "capability id contains an invalid character",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CapabilityIdError {}

#[derive(Clone, Copy, Debug, Eq, PartialOrd, Ord, PartialEq)]
pub(crate) enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApprovalFloor {
    RootEnabled,
    ExplicitPerAction,
    Forbidden,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScopeRequirement {
    None,
    WorkspaceRequired,
    NetworkDestinationRequired,
    ExternalResourceRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityDescriptor {
    capability_id: CapabilityId,
    display_name: String,
    risk_class: RiskClass,
    approval_floor: ApprovalFloor,
    scope_requirement: ScopeRequirement,
    execution_profile: Option<String>,
    tool_name: Option<String>,
    read_only: bool,
}

impl CapabilityDescriptor {
    fn new(
        capability_id: CapabilityId,
        display_name: impl Into<String>,
        risk_class: RiskClass,
        approval_floor: ApprovalFloor,
        scope_requirement: ScopeRequirement,
    ) -> Result<Self, CapabilityDescriptorError> {
        let display_name = display_name.into();
        if display_name.trim().is_empty() {
            return Err(CapabilityDescriptorError::EmptyDisplayName);
        }
        if display_name.chars().count() > MAX_DISPLAY_NAME_LENGTH {
            return Err(CapabilityDescriptorError::DisplayNameTooLong);
        }
        Ok(Self {
            capability_id,
            display_name,
            risk_class,
            approval_floor,
            scope_requirement,
            execution_profile: None,
            tool_name: None,
            read_only: false,
        })
    }

    fn with_execution_route(
        mut self,
        profile_id: impl Into<String>,
        tool_name: impl Into<String>,
    ) -> Self {
        self.execution_profile = Some(profile_id.into());
        self.tool_name = Some(tool_name.into());
        self.read_only = true;
        self
    }

    pub(crate) fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub(crate) fn display_name(&self) -> &str {
        &self.display_name
    }

    pub(crate) fn risk_class(&self) -> RiskClass {
        self.risk_class
    }

    pub(crate) fn approval_floor(&self) -> ApprovalFloor {
        self.approval_floor
    }

    pub(crate) fn scope_requirement(&self) -> ScopeRequirement {
        self.scope_requirement
    }

    pub(crate) fn execution_profile(&self) -> Option<&str> {
        self.execution_profile.as_deref()
    }

    pub(crate) fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    pub(crate) fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[cfg(any(
        test,
        feature = "d29-h3-host-fixture",
        feature = "d29-h4-host-fixture",
        feature = "d29-h5-host-fixture",
        feature = "d29-h7-host-fixture"
    ))]
    pub(crate) fn synthetic(
        capability_id: CapabilityId,
        display_name: impl Into<String>,
        risk_class: RiskClass,
        approval_floor: ApprovalFloor,
        scope_requirement: ScopeRequirement,
    ) -> Result<Self, CapabilityDescriptorError> {
        Self::new(
            capability_id,
            display_name,
            risk_class,
            approval_floor,
            scope_requirement,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityDescriptorError {
    EmptyDisplayName,
    DisplayNameTooLong,
}

impl fmt::Display for CapabilityDescriptorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EmptyDisplayName => "capability display name must not be empty",
            Self::DisplayNameTooLong => "capability display name is too long",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CapabilityDescriptorError {}

/// Immutable process-local registry built only from trusted static code.
/// There is deliberately no registration or replacement method after
/// construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityRegistry {
    descriptors: BTreeMap<CapabilityId, CapabilityDescriptor>,
}

impl CapabilityRegistry {
    fn from_trusted_descriptors(
        descriptors: impl IntoIterator<Item = CapabilityDescriptor>,
    ) -> Result<Self, CapabilityRegistryError> {
        let mut registry = BTreeMap::new();
        for descriptor in descriptors {
            let id = descriptor.capability_id.clone();
            if registry.insert(id.clone(), descriptor).is_some() {
                return Err(CapabilityRegistryError::DuplicateCapabilityId(id));
            }
        }
        Ok(Self {
            descriptors: registry,
        })
    }

    /// The production catalog is a closed, trusted static set.  H7-D opens
    /// exactly one read-only capability; no generic process, shell, write, or
    /// network descriptor is registered here.
    pub(crate) fn production() -> Result<Self, CapabilityRegistryError> {
        let capability_id = CapabilityId::try_from(PRODUCTION_GIT_STATUS_CAPABILITY_ID)
            .expect("the production Git status capability ID is a valid static identifier");
        let descriptor = CapabilityDescriptor::new(
            capability_id,
            "Governed read-only workspace Git status",
            RiskClass::Critical,
            ApprovalFloor::ExplicitPerAction,
            ScopeRequirement::WorkspaceRequired,
        )
        .expect("the production Git status descriptor is valid")
        .with_execution_route(
            PRODUCTION_GIT_STATUS_PROFILE_ID,
            PRODUCTION_GIT_STATUS_TOOL_NAME,
        );
        Self::from_trusted_descriptors([descriptor])
    }

    #[cfg(any(
        test,
        feature = "d29-h3-host-fixture",
        feature = "d29-h4-host-fixture",
        feature = "d29-h5-host-fixture",
        feature = "d29-h7-host-fixture"
    ))]
    pub(crate) fn synthetic(
        descriptors: impl IntoIterator<Item = CapabilityDescriptor>,
    ) -> Result<Self, CapabilityRegistryError> {
        Self::from_trusted_descriptors(descriptors)
    }

    pub(crate) fn descriptor(&self, capability_id: &CapabilityId) -> Option<&CapabilityDescriptor> {
        self.descriptors.get(capability_id)
    }

    #[cfg(any(
        test,
        feature = "d29-h1-host-fixture",
        feature = "d29-h3-host-fixture",
        feature = "d29-h4-host-fixture",
        feature = "d29-h5-host-fixture",
        feature = "d29-h7-host-fixture"
    ))]
    pub(crate) fn len(&self) -> usize {
        self.descriptors.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityRegistryError {
    DuplicateCapabilityId(CapabilityId),
}

impl fmt::Display for CapabilityRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCapabilityId(id) => {
                write!(formatter, "duplicate capability descriptor: {id}")
            }
        }
    }
}

impl std::error::Error for CapabilityRegistryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str) -> CapabilityDescriptor {
        CapabilityDescriptor::synthetic(
            CapabilityId::try_from(id).unwrap(),
            "Synthetic capability",
            RiskClass::Low,
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        )
        .unwrap()
    }

    #[test]
    fn capability_id_is_exact_lowercase_ascii_without_normalization() {
        for value in [
            "",
            "A",
            "capability id",
            "capability/id",
            "capability!",
            "é",
        ] {
            assert!(
                CapabilityId::try_from(value).is_err(),
                "{value:?} must fail"
            );
        }
        let id = CapabilityId::try_from("vision.observe-1").unwrap();
        assert_eq!(id.as_str(), "vision.observe-1");
        assert!(CapabilityId::try_from("VISION.OBSERVE-1").is_err());
        assert!(CapabilityId::try_from("a".repeat(MAX_CAPABILITY_ID_LENGTH + 1)).is_err());
    }

    #[test]
    fn trusted_registry_rejects_duplicates_and_has_no_runtime_registration_surface() {
        let error = CapabilityRegistry::synthetic([descriptor("test.one"), descriptor("test.one")])
            .unwrap_err();
        assert!(matches!(
            error,
            CapabilityRegistryError::DuplicateCapabilityId(_)
        ));
        let registry = CapabilityRegistry::production().unwrap();
        assert_eq!(registry.len(), 1);
        let git_status = CapabilityId::try_from(PRODUCTION_GIT_STATUS_CAPABILITY_ID).unwrap();
        let descriptor = registry.descriptor(&git_status).unwrap();
        assert_eq!(descriptor.risk_class(), RiskClass::Critical);
        assert_eq!(
            descriptor.approval_floor(),
            ApprovalFloor::ExplicitPerAction
        );
        assert_eq!(
            descriptor.scope_requirement(),
            ScopeRequirement::WorkspaceRequired
        );
        assert_eq!(
            descriptor.execution_profile(),
            Some(PRODUCTION_GIT_STATUS_PROFILE_ID)
        );
        assert_eq!(
            descriptor.tool_name(),
            Some(PRODUCTION_GIT_STATUS_TOOL_NAME)
        );
        assert!(descriptor.is_read_only());
        for excluded in [
            "vita.process.run",
            "vita.process.workspace.run",
            "vita.shell",
            "vita.git",
            "vita.write",
            "vita.network",
        ] {
            let id = CapabilityId::try_from(excluded).unwrap();
            assert!(
                registry.descriptor(&id).is_none(),
                "{excluded} must stay closed"
            );
        }
    }

    #[test]
    fn trusted_registry_reconstruction_is_deterministic_and_descriptor_owned() {
        let low = descriptor("test.low");
        let high = CapabilityDescriptor::synthetic(
            CapabilityId::try_from("test.high").unwrap(),
            "Synthetic high-risk capability",
            RiskClass::High,
            ApprovalFloor::ExplicitPerAction,
            ScopeRequirement::ExternalResourceRequired,
        )
        .unwrap();
        let first = CapabilityRegistry::synthetic([high.clone(), low.clone()]).unwrap();
        let second = CapabilityRegistry::synthetic([low, high.clone()]).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.descriptor(high.capability_id()), Some(&high));

        let altered = CapabilityDescriptor::synthetic(
            high.capability_id().clone(),
            high.display_name().to_owned(),
            RiskClass::Critical,
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        )
        .unwrap();
        assert_ne!(first.descriptor(altered.capability_id()), Some(&altered));
    }
}
