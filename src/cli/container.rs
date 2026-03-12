mod compose;
mod podman;
mod quadlet;
pub mod security_opt;

use clap::Args;
use color_eyre::eyre::{Context, OptionExt};
use compose_spec::service::Limit;

use crate::escape::command_join;

use self::{podman::PodmanArgs, quadlet::QuadletOptions, security_opt::SecurityOpt};

use super::image_to_name;

#[allow(clippy::doc_markdown)]
#[derive(Args, Default, Debug, Clone, PartialEq)]
pub struct Container {
    #[command(flatten)]
    quadlet_options: QuadletOptions,

    /// Converts to "PodmanArgs=ARGS"
    #[command(flatten)]
    podman_args: PodmanArgs,

    /// Security options
    ///
    /// Converts to a number of different Quadlet options or,
    /// if a Quadlet option for the specified security option doesn't exist,
    /// is placed in "PodmanArgs="
    ///
    /// Can be specified multiple times
    #[arg(long, value_name = "OPTION")]
    security_opt: Vec<SecurityOpt>,

    /// The image to run in the container
    ///
    /// Converts to "Image=IMAGE"
    image: String,

    /// Optionally, the command to run in the container
    ///
    /// Converts to "Exec=COMMAND..."
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

impl Container {
    /// The name that should be used for the generated [`File`](crate::quadlet::File).
    ///
    /// It is either the set container name or taken from the image.
    pub fn name(&self) -> &str {
        self.quadlet_options
            .name
            .as_deref()
            .unwrap_or_else(|| image_to_name(&self.image))
    }

    /// Set the `--pod` option.
    pub(super) fn set_pod(&mut self, pod: Option<String>) {
        self.podman_args.set_pod(pod);
    }
}

impl TryFrom<compose_spec::Service> for Container {
    type Error = color_eyre::Report;

    fn try_from(value: compose_spec::Service) -> Result<Self, Self::Error> {
        let compose::Service {
            unsupported,
            deploy,
            quadlet,
            podman_args,
            container:
                compose::Container {
                    command,
                    image,
                    security_opt,
                },
        } = compose::Service::from(value);

        unsupported.ensure_empty()?;

        let DeployResources {
            devices,
            memory,
            pids_limit,
            cpus,
            memory_reservation,
            cpu_shares,
            labels: deploy_labels,
        } = deploy
            .map(deploy_into_resources)
            .transpose()?
            .unwrap_or_default();

        let security_opt = security_opt
            .into_iter()
            .filter_map(|s| {
                if s == "no-new-privileges:true" {
                    Some(Ok(SecurityOpt::NoNewPrivileges))
                } else if s == "no-new-privileges:false" {
                    None
                } else {
                    Some(s.replacen(':', "=", 1).parse())
                }
            })
            .collect::<Result<_, _>>()
            .wrap_err("invalid security option")?;

        let mut quadlet_options: QuadletOptions = quadlet.try_into()?;
        quadlet_options.device.extend(devices);
        if quadlet_options.memory.is_none() {
            quadlet_options.memory = memory;
        }
        if quadlet_options.pids_limit.is_none() {
            quadlet_options.pids_limit = pids_limit;
        }
        quadlet_options.label.extend(deploy_labels);

        let mut podman_args: PodmanArgs = podman_args.try_into()?;
        if podman_args.cpus.is_none() {
            podman_args.cpus = cpus;
        }
        if podman_args.memory_reservation.is_none() {
            podman_args.memory_reservation = memory_reservation;
        }
        if podman_args.cpu_shares.is_none() {
            podman_args.cpu_shares = cpu_shares;
        }

        Ok(Self {
            quadlet_options,
            podman_args,
            security_opt,
            image: image.ok_or_eyre("`image` or `build` is required")?.into(),
            command: command
                .map(super::compose::command_try_into_vec)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// Resources extracted from [`compose_spec::service::Deploy`].
#[derive(Default)]
struct DeployResources {
    devices: Vec<crate::quadlet::container::Device>,
    memory: Option<String>,
    pids_limit: Option<Limit<u32>>,
    cpus: Option<f64>,
    memory_reservation: Option<String>,
    cpu_shares: Option<u64>,
    labels: Vec<String>,
}

/// Extract resources from [`compose_spec::service::Deploy`] and convert them to quadlet/podman
/// fields. Unsupported deploy fields cause an error.
#[allow(clippy::too_many_lines)]
fn deploy_into_resources(
    deploy: compose_spec::service::Deploy,
) -> color_eyre::Result<DeployResources> {
    use color_eyre::eyre::ensure;

    let compose_spec::service::Deploy {
        endpoint_mode: _,
        labels,
        mode: _,
        placement: _,
        replicas: _,
        resources,
        restart_policy: _,
        rollback_config: _,
        update_config: _,
        extensions,
    } = deploy;

    ensure!(extensions.is_empty(), "compose extensions are not supported");

    let deploy_labels: Vec<String> = labels.into_list().into_iter().collect();

    let Some(resources) = resources else {
        return Ok(DeployResources {
            devices: Vec::new(),
            memory: None,
            pids_limit: None,
            cpus: None,
            memory_reservation: None,
            cpu_shares: None,
            labels: deploy_labels,
        });
    };

    let compose_spec::service::deploy::Resources {
        limits,
        reservations,
        extensions,
    } = resources;

    ensure!(extensions.is_empty(), "compose extensions are not supported");

    let (result_memory, result_pids_limit, result_cpus) = if let Some(limits) = limits {
        let compose_spec::service::deploy::resources::Limits {
            cpus,
            memory,
            pids,
            extensions,
        } = limits;
        ensure!(extensions.is_empty(), "compose extensions are not supported");
        (
            memory.map(|m| m.to_string()),
            pids,
            cpus.map(f64::from),
        )
    } else {
        (None, None, None)
    };

    let Some(reservations) = reservations else {
        return Ok(DeployResources {
            devices: Vec::new(),
            memory: result_memory,
            pids_limit: result_pids_limit,
            cpus: result_cpus,
            memory_reservation: None,
            cpu_shares: None,
            labels: deploy_labels,
        });
    };

    let compose_spec::service::deploy::resources::Reservations {
        cpus: reservations_cpus,
        memory: reservations_memory,
        devices,
        generic_resources,
        extensions,
    } = reservations;
    let result_memory_reservation = reservations_memory.map(|m| m.to_string());
    ensure!(
        generic_resources.is_empty(),
        "`deploy.resources.reservations.generic_resources` is not supported"
    );
    ensure!(extensions.is_empty(), "compose extensions are not supported");

    let mut result = Vec::new();

    for device in devices {
        let compose_spec::service::deploy::resources::Device {
            capabilities,
            driver,
            count,
            device_ids,
            options,
            extensions,
        } = device;

        ensure!(options.is_empty(), "`deploy.resources.reservations.devices.options` is not supported");
        ensure!(extensions.is_empty(), "compose extensions are not supported");

        let driver = driver.as_deref().unwrap_or("nvidia");

        // `count` and `device_ids` are mutually exclusive per the compose spec.
        // When `device_ids` is set, each ID produces a CDI device per capability.
        // When `count` is set (or neither), use count for all capabilities.
        let identifiers: Vec<String> = if device_ids.is_empty() {
            let count = match count {
                Some(compose_spec::service::deploy::resources::Count::All) | None => {
                    "all".to_owned()
                }
                Some(compose_spec::service::deploy::resources::Count::Integer(n)) => n.to_string(),
            };
            vec![count]
        } else {
            device_ids.into_iter().collect()
        };

        for capability in &capabilities {
            for id in &identifiers {
                let cdi = format!("{driver}.com/{capability}={id}");
                result.push(crate::quadlet::container::Device {
                    host: cdi.into(),
                    container: None,
                    read: false,
                    write: false,
                    mknod: false,
                });
            }
        }
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let result_cpu_shares =
        reservations_cpus.map(|c| (f64::from(c) * 1024.0).round() as u64);

    Ok(DeployResources {
        devices: result,
        memory: result_memory,
        pids_limit: result_pids_limit,
        cpus: result_cpus,
        memory_reservation: result_memory_reservation,
        cpu_shares: result_cpu_shares,
        labels: deploy_labels,
    })
}

impl From<Container> for crate::quadlet::Container {
    fn from(
        Container {
            quadlet_options,
            podman_args,
            security_opt,
            image,
            command,
        }: Container,
    ) -> Self {
        let mut podman_args = podman_args.to_string();

        let security_opt::QuadletOptions {
            mask,
            no_new_privileges,
            seccomp_profile,
            security_label_disable,
            security_label_file_type,
            security_label_level,
            security_label_nested,
            security_label_type,
            unmask,
            podman_args: security_podman_args,
        } = security_opt.into_iter().fold(
            security_opt::QuadletOptions::default(),
            |mut security_options, security_opt| {
                security_options.add_security_opt(security_opt);
                security_options
            },
        );

        for arg in security_podman_args {
            podman_args.push_str(" --security-opt ");
            podman_args.push_str(&arg);
        }

        Self {
            image,
            mask,
            no_new_privileges,
            seccomp_profile,
            security_label_disable,
            security_label_file_type,
            security_label_level,
            security_label_nested,
            security_label_type,
            unmask,
            podman_args: (!podman_args.is_empty()).then(|| podman_args.trim().to_string()),
            exec: (!command.is_empty()).then(|| command_join(command)),
            ..quadlet_options.into()
        }
    }
}

impl From<Container> for crate::quadlet::Resource {
    fn from(value: Container) -> Self {
        crate::quadlet::Container::from(value).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod deploy {
        use super::*;

        fn container_from_yaml(yaml: &str) -> color_eyre::Result<Container> {
            let service: compose_spec::Service = serde_yaml::from_str(yaml).unwrap();
            Container::try_from(service)
        }

        #[test]
        fn reservations_memory_becomes_memory_reservation() {
            let container = container_from_yaml(
                "image: test\ndeploy:\n  resources:\n    reservations:\n      memory: 256m\n",
            )
            .unwrap();
            assert_eq!(
                container.podman_args.memory_reservation.as_deref(),
                Some("256mb"),
                "reservations.memory should map to --memory-reservation",
            );
        }

        #[test]
        fn reservations_cpus_becomes_cpu_shares() {
            let container = container_from_yaml(
                "image: test\ndeploy:\n  resources:\n    reservations:\n      cpus: 2.0\n",
            )
            .unwrap();
            assert_eq!(
                container.podman_args.cpu_shares,
                Some(2048),
                "reservations.cpus should map to --cpu-shares (cpus * 1024)",
            );
        }

        #[test]
        fn deploy_labels_extend_container_labels() {
            let container = container_from_yaml(
                "image: test\ndeploy:\n  labels:\n    - foo=bar\n",
            )
            .unwrap();
            assert!(
                container.quadlet_options.label.contains(&"foo=bar".to_owned()),
                "deploy.labels should extend container labels",
            );
        }

    }

    mod name {
        use super::*;

        #[test]
        fn container_name() {
            let name = "test";
            let mut sut = Container::default();
            sut.quadlet_options.name = Some(String::from(name));

            assert_eq!(sut.name(), name);
        }

        #[test]
        fn image_no_tag() {
            let sut = Container {
                image: String::from("quay.io/podman/hello"),
                ..Default::default()
            };
            assert_eq!(sut.name(), "hello");
        }

        #[test]
        fn image_with_tag() {
            let sut = Container {
                image: String::from("quay.io/podman/hello:latest"),
                ..Default::default()
            };
            assert_eq!(sut.name(), "hello");
        }
    }
}
