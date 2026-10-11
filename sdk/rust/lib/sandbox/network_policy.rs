//! Replacing a running sandbox's network policy.

use microsandbox_control_client::{NetworkPolicyUpdate, UpdateNetworkPolicy};

use super::NetworkPolicy;
use crate::backend::Backend;
use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Send `policy` to the running sandbox's runtime over its control channel.
pub(super) async fn set(
    backend: &dyn Backend,
    name: &str,
    policy: &NetworkPolicy,
) -> MicrosandboxResult<()> {
    let unsupported = |reason| MicrosandboxError::Unsupported {
        op: Operation::SandboxSetNetworkPolicy,
        reason,
    };
    let local = backend
        .as_local()
        .ok_or_else(|| unsupported(UnsupportedReason::LocalOnly))?;
    let session = local
        .control_session(name)
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotRunning(name.into()))?;
    if !session.capabilities().network_policy_update {
        return Err(unsupported(UnsupportedReason::NotAvailable(
            "this sandbox's runtime cannot replace its network policy".into(),
        )));
    }
    let policy: microsandbox_types::NetworkPolicy =
        serde_json::from_value(serde_json::to_value(policy)?)?;
    session
        .request(&UpdateNetworkPolicy(NetworkPolicyUpdate { policy }))
        .await
        .map_err(MicrosandboxError::ControlClient)?;
    Ok(())
}
