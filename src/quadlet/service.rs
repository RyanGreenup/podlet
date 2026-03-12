use clap::{Args, ValueEnum};
use compose_spec::service::Restart;
use serde::Serialize;

/// The `[Service]` section of a systemd unit / Quadlet file.
///
/// Only includes options needed to convert [Podman CLI](crate::cli::PodmanCommands) and
/// [`Compose`](compose_spec::Compose) files.
#[derive(Args, Serialize, Default, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Service {
    /// Configure if and when the service should be restarted.
    #[arg(long, value_name = "POLICY")]
    pub restart: Option<RestartConfig>,

    /// Commands to run after the main container process starts.
    #[arg(skip)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exec_start_post: Vec<String>,

    /// Commands to run to stop the service.
    #[arg(skip)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exec_stop: Vec<String>,

    /// Maximum number of times to attempt to restart the service.
    #[arg(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_limit_burst: Option<u64>,
}

impl Service {
    /// Returns `true` if all fields are unset or empty.
    pub fn is_empty(&self) -> bool {
        let Self {
            restart,
            exec_start_post,
            exec_stop,
            start_limit_burst,
        } = self;

        restart.is_none()
            && exec_start_post.is_empty()
            && exec_stop.is_empty()
            && start_limit_burst.is_none()
    }
}

impl From<RestartConfig> for Service {
    fn from(restart: RestartConfig) -> Self {
        Self {
            restart: Some(restart),
            ..Self::default()
        }
    }
}

impl From<Restart> for Service {
    fn from(restart: Restart) -> Self {
        RestartConfig::from(restart).into()
    }
}

/// Possible service restart configurations.
///
/// From [systemd.service](https://www.freedesktop.org/software/systemd/man/systemd.service.html#Restart=).
#[derive(ValueEnum, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartConfig {
    No,
    OnSuccess,
    OnFailure,
    OnAbnormal,
    OnWatchdog,
    OnAbort,
    #[value(alias = "unless-stopped")]
    Always,
}

impl From<Restart> for RestartConfig {
    fn from(value: Restart) -> Self {
        match value {
            Restart::No => Self::No,
            Restart::Always | Restart::UnlessStopped => Self::Always,
            Restart::OnFailure => Self::OnFailure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_with_hooks_serializes() -> Result<(), crate::serde::quadlet::Error> {
        let service = Service {
            exec_start_post: vec!["podman exec systemd-%N pg_isready -U postgres".into()],
            exec_stop: vec!["podman exec systemd-%N pg_ctl stop -m fast".into()],
            ..Service::default()
        };
        assert_eq!(
            crate::serde::quadlet::to_string_join_all(service)?,
            "[Service]\nExecStartPost=podman exec systemd-%N pg_isready -U postgres\nExecStop=podman exec systemd-%N pg_ctl stop -m fast\n"
        );
        Ok(())
    }

    #[test]
    fn empty_service_is_empty() {
        assert!(Service::default().is_empty());
    }

    #[test]
    fn service_with_exec_start_post_not_empty() {
        let service = Service {
            exec_start_post: vec!["cmd".into()],
            ..Service::default()
        };
        assert!(!service.is_empty());
    }
}
