use std::{
    collections::HashMap,
    fs,
    io::{self, IsTerminal},
    iter, mem,
    path::{Path, PathBuf},
};

use clap::Args;
use color_eyre::{
    Help,
    eyre::{OptionExt, WrapErr, bail, ensure, eyre},
};
use compose_spec::{
    Identifier, Network, Networks, Options, Resource, Service, Volumes, service::Command,
};
use indexmap::IndexMap;

use serde::Deserialize;

use crate::quadlet::{self, GenericSections, Globals, container::volume::Source};

use super::{Build, Container, File, GlobalArgs, k8s};

/// The `environment` field of a lifecycle hook entry, which can be a list or a map.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
enum HookEnvironment {
    List(Vec<String>),
    Map(IndexMap<String, Option<String>>),
}

impl HookEnvironment {
    fn env_args(&self) -> Vec<String> {
        match self {
            Self::List(list) => list.clone(),
            Self::Map(map) => map
                .iter()
                .map(|(k, v)| match v {
                    Some(val) => format!("{k}={val}"),
                    None => k.clone(),
                })
                .collect(),
        }
    }
}

/// A single lifecycle hook entry from a compose file.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
struct HookEntry {
    command: Vec<String>,
    user: Option<String>,
    privileged: bool,
    working_dir: Option<String>,
    environment: Option<HookEnvironment>,
}

/// Lifecycle hooks extracted from a compose service.
#[derive(Default, Debug, Clone)]
struct LifecycleHooks {
    post_start: Vec<HookEntry>,
    pre_stop: Vec<HookEntry>,
}

impl LifecycleHooks {
    /// Convert lifecycle hooks into systemd `ExecStartPost=` and `ExecStop=` commands.
    ///
    /// Each command is wrapped with `podman exec {container_name}` so it runs inside the
    /// container. Pass `"systemd-%N"` when no explicit `ContainerName=` is set; that matches
    /// the quadlet default (see `ContainerName=` in podman-systemd.unit(5)).
    fn to_service_fields(
        &self,
        container_name: &str,
    ) -> color_eyre::Result<(Vec<String>, Vec<String>)> {
        let to_exec = |entry: &HookEntry| -> color_eyre::Result<String> {
            let mut args: Vec<String> = vec!["podman".into(), "exec".into()];
            if let Some(user) = &entry.user {
                args.push("--user".into());
                args.push(user.clone());
            }
            if entry.privileged {
                args.push("--privileged".into());
            }
            if let Some(wd) = &entry.working_dir {
                args.push("--workdir".into());
                args.push(wd.clone());
            }
            if let Some(env) = &entry.environment {
                for var in env.env_args() {
                    args.push("--env".into());
                    args.push(var);
                }
            }
            args.push(container_name.into());
            args.extend(entry.command.iter().cloned());
            shlex::try_join(args.iter().map(String::as_str))
                .map_err(|e| eyre!("lifecycle hook command contains an unsupported argument: {e}"))
        };
        let exec_start_post = self.post_start.iter().map(to_exec).collect::<color_eyre::Result<_>>()?;
        let exec_stop = self.pre_stop.iter().map(to_exec).collect::<color_eyre::Result<_>>()?;
        Ok((exec_start_post, exec_stop))
    }
}

/// Extract `post_start` and `pre_stop` lifecycle hooks from the YAML value.
///
/// These keys are not recognized by `compose_spec` v0.3.0 and must be removed before
/// deserialization. Returns a map of service name to hooks.
fn extract_lifecycle_hooks(
    value: &mut serde_yaml::Value,
) -> color_eyre::Result<HashMap<String, LifecycleHooks>> {
    let mut hooks_map = HashMap::new();

    let Some(serde_yaml::Value::Mapping(services)) = value.get_mut("services") else {
        return Ok(hooks_map);
    };

    for (name, service) in services.iter_mut() {
        let Some(name) = name.as_str().map(ToOwned::to_owned) else {
            continue;
        };

        let Some(service_map) = service.as_mapping_mut() else {
            continue;
        };

        let mut hooks = LifecycleHooks::default();

        if let Some(post_start) = service_map
            .remove(serde_yaml::Value::String("post_start".into()))
        {
            hooks.post_start = serde_yaml::from_value::<Vec<HookEntry>>(post_start)
                .wrap_err_with(|| {
                    format!("invalid `post_start` hooks for service `{name}`")
                })?;
        }

        if let Some(pre_stop) = service_map
            .remove(serde_yaml::Value::String("pre_stop".into()))
        {
            hooks.pre_stop = serde_yaml::from_value::<Vec<HookEntry>>(pre_stop)
                .wrap_err_with(|| {
                    format!("invalid `pre_stop` hooks for service `{name}`")
                })?;
        }

        if !hooks.post_start.is_empty() || !hooks.pre_stop.is_empty() {
            hooks_map.insert(name, hooks);
        }
    }

    Ok(hooks_map)
}

/// Converts a [`Command`] into a [`Vec<String>`], splitting the [`String`](Command::String) variant
/// as a shell would.
///
/// # Errors
///
/// Returns an error if, while splitting the string variant, the command ends while in a quote or
/// has a trailing unescaped '\\'.
pub fn command_try_into_vec(command: Command) -> color_eyre::Result<Vec<String>> {
    match command {
        Command::String(command) => shlex::split(&command)
            .ok_or_else(|| eyre!("invalid command: `{command}`"))
            .suggestion(
                "In the command, make sure quotes are closed properly and there are no \
                    trailing \\. Alternatively, use an array instead of a string.",
            ),
        Command::List(command) => Ok(command),
    }
}

/// [`Args`] for the `podlet compose` subcommand.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct Compose {
    /// Create a `.pod` file and link it with each `.container` file.
    ///
    /// The top-level `name` field in the compose file is required when using this option.
    /// It is used for the name of the pod and in the filenames of the created files.
    ///
    /// Each container becomes a part of the pod and is renamed to "{pod}-{container}".
    ///
    /// Published ports are taken from each container and applied to the pod.
    #[arg(long, conflicts_with = "kube")]
    pub pod: bool,

    /// Create a Kubernetes YAML file for a pod instead of separate containers
    ///
    /// A `.kube` file using the generated Kubernetes YAML file is also created.
    ///
    /// The top-level `name` field in the compose file is required when using this option.
    /// It is used for the name of the pod and in the filenames of the created files.
    #[arg(long, conflicts_with = "pod")]
    pub kube: bool,

    /// The compose file to convert
    ///
    /// If `-` or not provided and stdin is not a terminal,
    /// the compose file will be read from stdin.
    ///
    /// If not provided, and stdin is a terminal, Podlet will look for (in order)
    /// `compose.yaml`, `compose.yml`, `docker-compose.yaml`, `docker-compose.yml`,
    /// `podman-compose.yaml`, and `podman-compose.yml`,
    /// in the current working directory.
    #[allow(clippy::struct_field_names)]
    pub compose_file: Option<PathBuf>,
}

impl Compose {
    /// Attempt to convert the `compose_file` into [`File`]s.
    ///
    /// # Errors
    ///
    /// Returns an error if there was an error:
    ///
    /// - Reading/deserializing the compose file.
    /// - Converting the compose file to Kubernetes YAML.
    /// - Converting the compose file to Quadlet files.
    pub fn try_into_files(self, sections: GenericSections) -> color_eyre::Result<Vec<File>> {
        let Self {
            pod,
            kube,
            compose_file,
        } = self;

        let mut options = compose_spec::Compose::options();
        options.apply_merge(true);
        let (compose, lifecycle_hooks) =
            read_from_file_or_stdin(compose_file.as_deref(), &options)
                .wrap_err("error reading compose file")?;
        compose
            .validate_all()
            .wrap_err("error validating compose file")?;

        if kube {
            let mut k8s_file = k8s::File::try_from(compose)
                .wrap_err("error converting compose file into Kubernetes YAML")?;

            let GenericSections {
                unit,
                quadlet,
                install,
            } = sections;
            let kube =
                quadlet::Kube::new(PathBuf::from(format!("{}-kube.yaml", k8s_file.name)).into());
            let quadlet_file = quadlet::File {
                name: k8s_file.name.clone(),
                unit,
                resource: kube.into(),
                globals: Globals::default(),
                quadlet,
                service: quadlet::Service::default(),
                install,
            };

            k8s_file.name.push_str("-kube");
            Ok(vec![quadlet_file.into(), k8s_file.into()])
        } else {
            let compose_spec::Compose {
                version: _,
                name,
                include,
                services,
                networks,
                volumes,
                configs,
                secrets,
                extensions,
            } = compose;

            let pod_name = pod
                .then(|| name.ok_or_eyre("`name` is required when using `--pod`"))
                .transpose()?
                .map(Into::into);

            ensure!(include.is_empty(), "`include` is not supported");
            ensure!(configs.is_empty(), "`configs` is not supported");
            ensure!(
                secrets.values().all(Resource::is_external),
                "only external `secrets` are supported",
            );
            ensure!(
                extensions.is_empty(),
                "compose extensions are not supported"
            );

            parts_try_into_files(services, networks, volumes, pod_name, sections, &lifecycle_hooks)
                .wrap_err("error converting compose file into Quadlet files")
        }
    }
}

/// Read and deserialize a [`compose_spec::Compose`] from a file at the given [`Path`], stdin, or a
/// list of default files.
///
/// If the path is '-', or stdin is not a terminal, the compose file is deserialized from stdin.
/// If a path is not provided, the files `compose.yaml`, `compose.yml`, `docker-compose.yaml`,
/// `docker-compose.yml`, `podman-compose.yaml`, and `podman-compose.yml` are, in order, looked for
///  in the current directory.
///
/// # Errors
///
/// Returns an error if:
///
/// - There was an error opening the given file.
/// - Stdin was selected and stdin is a terminal.
/// - No path was given and none of the default files could be opened.
/// - There was an error deserializing [`compose_spec::Compose`].
fn read_from_file_or_stdin(
    path: Option<&Path>,
    options: &Options,
) -> color_eyre::Result<(compose_spec::Compose, HashMap<String, LifecycleHooks>)> {
    if let Some(path) = path {
        if path.as_os_str() == "-" {
            return read_from_stdin(options);
        }
        let file = fs::File::open(path)
            .wrap_err("could not open provided compose file")
            .suggestion("make sure you have the proper permissions for the given file")?;
        return parse_compose(file, options, &path.display().to_string());
    }

    if !io::stdin().is_terminal() {
        return read_from_stdin(options);
    }

    const FILE_NAMES: [&str; 6] = [
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
        "podman-compose.yaml",
        "podman-compose.yml",
    ];

    for file_name in FILE_NAMES {
        if let Ok(file) = fs::File::open(file_name) {
            return parse_compose(file, options, file_name);
        }
    }

    Err(eyre!(
        "a compose file was not provided and none of \
            `compose.yaml`, `compose.yml`, `docker-compose.yaml`, `docker-compose.yml`, \
            `podman-compose.yaml`, or `podman-compose.yml` exist in the current directory or \
            could not be read"
    ))
}

/// Parse a compose file from `reader`, extracting lifecycle hooks before deserialization.
///
/// `source` is used only for error messages (e.g. a file path or `"stdin"`).
///
/// # Errors
///
/// Returns an error if the reader does not contain valid YAML or a valid compose file.
fn parse_compose(
    reader: impl io::Read,
    options: &Options,
    source: &str,
) -> color_eyre::Result<(compose_spec::Compose, HashMap<String, LifecycleHooks>)> {
    let mut value: serde_yaml::Value = serde_yaml::from_reader(reader)
        .wrap_err_with(|| format!("`{source}` is not valid YAML"))?;

    let hooks = extract_lifecycle_hooks(&mut value)?;

    let compose = options
        .from_yaml_value(value)
        .wrap_err_with(|| format!("`{source}` is not a valid compose file"))?;

    Ok((compose, hooks))
}

/// Read and deserialize [`compose_spec::Compose`] from stdin.
///
/// # Errors
///
/// Returns an error if stdin is a terminal or there was an error deserializing.
fn read_from_stdin(
    options: &Options,
) -> color_eyre::Result<(compose_spec::Compose, HashMap<String, LifecycleHooks>)> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        bail!("cannot read compose from stdin, stdin is a terminal");
    }

    parse_compose(stdin, options, "stdin")
}

/// Attempt to convert [`Service`]s, [`Networks`], and [`Volumes`] into [`File`]s.
///
/// # Errors
///
/// Returns an error if a [`Service`], [`Network`], or [`Volume`](compose_spec::Volume) could not be
/// converted into a [`quadlet::File`].
fn parts_try_into_files(
    services: IndexMap<Identifier, Service>,
    networks: Networks,
    volumes: Volumes,
    pod_name: Option<String>,
    sections: GenericSections,
    lifecycle_hooks: &HashMap<String, LifecycleHooks>,
) -> color_eyre::Result<Vec<File>> {
    // Get a map of volumes to whether the volume has options associated with it for use in
    // converting a service into a Quadlet file. Extra volume options must be specified in a
    // separate Quadlet file which is referenced from the container Quadlet file.
    let volume_has_options = volumes
        .iter()
        .map(|(name, volume)| {
            let has_options = volume
                .as_ref()
                .and_then(Resource::as_compose)
                .is_some_and(|volume| !volume.is_empty());
            (name.clone(), has_options)
        })
        .collect();

    let mut pod_ports = Vec::new();
    let mut files = services_try_into_quadlet_files(
        services,
        &sections,
        &volume_has_options,
        pod_name.as_deref(),
        &mut pod_ports,
        lifecycle_hooks,
    )
    .chain(networks_try_into_quadlet_files(networks, &sections))
    .chain(volumes_try_into_quadlet_files(volumes, &sections))
    .map(|result| result.map(Into::into))
    .collect::<Result<Vec<File>, _>>()?;

    if let Some(name) = pod_name {
        let GenericSections {
            unit,
            quadlet,
            install,
        } = sections;
        let pod = quadlet::Pod {
            publish_port: pod_ports,
            ..quadlet::Pod::default()
        };
        let pod = quadlet::File {
            name,
            unit,
            resource: pod.into(),
            globals: Globals::default(),
            quadlet,
            service: quadlet::Service::default(),
            install,
        };
        files.push(pod.into());
    }

    Ok(files)
}

/// Attempt to convert Compose [`Service`]s into [`quadlet::File`]s.
///
/// `volume_has_options` should be a map from volume [`Identifier`]s to whether the volume has any
/// options set. It is used to determine whether to link to a [`quadlet::Volume`] in the created
/// [`quadlet::Container`].
///
/// If `pod_name` is [`Some`] and a service has any published ports, they are taken from the
/// created [`quadlet::Container`] and added to `pod_ports`.
///
/// # Errors
///
/// Returns an error if there was an error [adding](Unit::add_dependency()) a service
/// [`Dependency`](compose_spec::service::Dependency) to the [`Unit`], converting the
/// [`Build`](compose_spec::service::Build) section into a [`quadlet::Build`] file, or converting
/// the [`Service`] into a [`quadlet::Container`] file.
fn services_try_into_quadlet_files<'a>(
    services: IndexMap<Identifier, Service>,
    sections @ GenericSections {
        unit,
        quadlet,
        install,
    }: &'a GenericSections,
    volume_has_options: &'a HashMap<Identifier, bool>,
    pod_name: Option<&'a str>,
    pod_ports: &'a mut Vec<String>,
    lifecycle_hooks: &'a HashMap<String, LifecycleHooks>,
) -> impl Iterator<Item = color_eyre::Result<quadlet::File>> + 'a {
    services.into_iter().flat_map(move |(name, mut service)| {
        if service.image.is_some() && service.build.is_some() {
            return iter::once(Err(eyre!(
                "error converting service `{name}`: `image` and `build` cannot both be set"
            )))
            .chain(None);
        }

        let build = service.build.take().map(|build| {
            let build = Build::try_from(build.into_long()).wrap_err_with(|| {
                format!(
                    "error converting `build` for service `{name}` into a Quadlet `.build` file"
                )
            })?;
            let image = format!("{}.build", build.name()).try_into()?;
            service.image = Some(image);
            Ok(quadlet::File {
                name: build.name().to_owned(),
                unit: unit.clone(),
                resource: build.into(),
                globals: Globals::default(),
                quadlet: *quadlet,
                service: quadlet::Service::default(),
                install: install.clone(),
            })
        });
        if let Some(result @ Err(_)) = build {
            return iter::once(result).chain(None);
        }

        let container = service_try_into_quadlet_file(
            service,
            name,
            sections.clone(),
            volume_has_options,
            pod_name,
            pod_ports,
            lifecycle_hooks,
        );

        iter::once(container).chain(build)
    })
}

/// Attempt to convert a compose [`Service`] into a [`quadlet::File`].
///
/// `volume_has_options` should be a map from volume [`Identifier`]s to whether the volume has any
/// options set. It is used to determine whether to link to a [`quadlet::Volume`] in the created
/// [`quadlet::Container`].
///
/// If `pod_name` is [`Some`] and the `service` has any published ports, they are taken from the
/// created [`quadlet::Container`] and added to `pod_ports`.
///
/// # Errors
///
/// Returns an error if there was an error [adding](Unit::add_dependency()) a service
/// [`Dependency`](compose_spec::service::Dependency) to the [`Unit`] or converting the [`Service`]
/// into a [`quadlet::Container`].
fn service_try_into_quadlet_file(
    mut service: Service,
    name: Identifier,
    GenericSections {
        mut unit,
        quadlet,
        install,
    }: GenericSections,
    volume_has_options: &HashMap<Identifier, bool>,
    pod_name: Option<&str>,
    pod_ports: &mut Vec<String>,
    lifecycle_hooks: &HashMap<String, LifecycleHooks>,
) -> color_eyre::Result<quadlet::File> {
    // Add any service dependencies to the [Unit] section of the Quadlet file.
    let dependencies = mem::take(&mut service.depends_on).into_long();
    if !dependencies.is_empty() {
        for (ident, dependency) in dependencies {
            unit.add_dependency(
                pod_name.map_or_else(
                    || ident.to_string(),
                    |pod_name| format!("{pod_name}-{ident}"),
                ),
                dependency,
            )
            .wrap_err_with(|| {
                format!("error adding dependency on `{ident}` to service `{name}`")
            })?;
        }
    }

    let global_args = GlobalArgs::from_compose(&mut service);

    let restart = service.restart;

    let mut container = Container::try_from(service)
        .map(quadlet::Container::from)
        .wrap_err_with(|| format!("error converting service `{name}` into a Quadlet container"))?;

    // For each named volume, check to see if it has any options set.
    // If it does, add `.volume` to the source to link this `.container` file to the generated
    // `.volume` file.
    for volume in &mut container.volume {
        if let Some(Source::NamedVolume(source)) = &mut volume.source {
            let volume_has_options = volume_has_options
                .get(source.as_str())
                .copied()
                .unwrap_or_default();
            if volume_has_options {
                source.push_str(".volume");
            }
        }
    }

    let mut service = restart
        .map(quadlet::Service::from)
        .unwrap_or_default();

    if let Some(hooks) = lifecycle_hooks.get(name.as_str()) {
        let container_name = container
            .container_name
            .as_deref()
            .unwrap_or("systemd-%N");
        let (exec_start_post, exec_stop) = hooks
            .to_service_fields(container_name)
            .wrap_err_with(|| format!("error converting lifecycle hooks for service `{name}`"))?;
        service.exec_start_post = exec_start_post;
        service.exec_stop = exec_stop;
    }

    let name = if let Some(pod_name) = pod_name {
        container.pod = Some(format!("{pod_name}.pod"));
        pod_ports.extend(mem::take(&mut container.publish_port));
        format!("{pod_name}-{name}")
    } else {
        name.into()
    };

    Ok(quadlet::File {
        name,
        unit,
        resource: container.into(),
        globals: global_args.into(),
        quadlet,
        service,
        install,
    })
}

/// Attempt to convert compose [`Networks`] into an [`Iterator`] of [`quadlet::File`]s.
///
/// # Errors
///
/// The [`Iterator`] returns an [`Err`] if a [`Network`] could not be converted into a
/// [`quadlet::Network`].
fn networks_try_into_quadlet_files(
    networks: Networks,
    GenericSections {
        unit,
        quadlet,
        install,
    }: &GenericSections,
) -> impl Iterator<Item = color_eyre::Result<quadlet::File>> {
    networks.into_iter().map(move |(name, network)| {
        let network = match network {
            Some(Resource::Compose(network)) => network,
            None => Network::default(),
            Some(Resource::External { .. }) => {
                bail!("external networks (`{name}`) are not supported");
            }
        };
        let network = quadlet::Network::try_from(network).wrap_err_with(|| {
            format!("error converting network `{name}` into a Quadlet network")
        })?;

        Ok(quadlet::File {
            name: name.into(),
            unit: unit.clone(),
            resource: network.into(),
            globals: Globals::default(),
            quadlet: *quadlet,
            service: quadlet::Service::default(),
            install: install.clone(),
        })
    })
}

/// Attempt to convert compose [`Volumes`] into an [`Iterator`] of [`quadlet::File`]s.
///
/// [`Volume`](compose_spec::Volume)s which are [empty](compose_spec::Volume::is_empty()) are
/// filtered out as they do not need a `.volume` Quadlet file to define extra options.
///
/// # Errors
///
/// The [`Iterator`] returns an [`Err`] if a [`Volume`](compose_spec::Volume) could not be converted
/// to a [`quadlet::Volume`].
fn volumes_try_into_quadlet_files(
    volumes: Volumes,
    GenericSections {
        unit,
        quadlet,
        install,
    }: &GenericSections,
) -> impl Iterator<Item = color_eyre::Result<quadlet::File>> {
    volumes.into_iter().filter_map(move |(name, volume)| {
        volume.and_then(|volume| match volume {
            Resource::Compose(volume) => (!volume.is_empty()).then(|| {
                quadlet::Volume::try_from(volume)
                    .wrap_err_with(|| {
                        format!("error converting volume `{name}` into a Quadlet volume")
                    })
                    .map(|volume| quadlet::File {
                        name: name.into(),
                        unit: unit.clone(),
                        resource: volume.into(),
                        globals: Globals::default(),
                        quadlet: *quadlet,
                        service: quadlet::Service::default(),
                        install: install.clone(),
                    })
            }),
            Resource::External { .. } => {
                Some(Err(eyre!("external volumes (`{name}`) are not supported")))
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hooks_post_start_and_pre_stop() {
        let yaml = r#"
services:
  app:
    image: example
    post_start:
      - command: ["pg_isready", "-U", "postgres"]
    pre_stop:
      - command: ["pg_ctl", "stop", "-m", "fast"]
"#;
        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let hooks = extract_lifecycle_hooks(&mut value).unwrap();
        let app_hooks = hooks.get("app").unwrap();
        assert_eq!(
            app_hooks.post_start[0].command,
            vec!["pg_isready", "-U", "postgres"]
        );
        assert_eq!(
            app_hooks.pre_stop[0].command,
            vec!["pg_ctl", "stop", "-m", "fast"]
        );
    }

    #[test]
    fn extract_hooks_removes_keys_from_value() {
        let yaml = r#"
services:
  app:
    image: example
    post_start:
      - command: ["echo", "hi"]
"#;
        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        extract_lifecycle_hooks(&mut value).unwrap();
        // post_start key should be gone so compose_spec won't choke on it
        let svc = &value["services"]["app"];
        assert!(svc.get("post_start").is_none());
    }

    #[test]
    fn extract_hooks_malformed_returns_error() {
        let yaml = r#"
services:
  app:
    image: example
    post_start: "not-a-list"
"#;
        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(extract_lifecycle_hooks(&mut value).is_err());
    }

    #[test]
    fn to_service_fields_formats_with_systemd_specifier() {
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["pg_isready".into(), "-U".into(), "postgres".into()],
                ..Default::default()
            }],
            pre_stop: vec![HookEntry {
                command: vec!["pg_ctl".into(), "stop".into(), "-m".into(), "fast".into()],
                ..Default::default()
            }],
        };
        let (start_post, stop) = hooks.to_service_fields("systemd-%N").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec 'systemd-%N' pg_isready -U postgres"]
        );
        assert_eq!(stop, vec!["podman exec 'systemd-%N' pg_ctl stop -m fast"]);
    }

    #[test]
    fn extract_hooks_multiple_entries_all_collected() {
        let yaml = r#"
services:
  app:
    image: example
    post_start:
      - command: ["step1"]
      - command: ["step2", "--flag"]
    pre_stop:
      - command: ["cleanup1"]
      - command: ["cleanup2", "--force"]
"#;
        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let hooks = extract_lifecycle_hooks(&mut value).unwrap();
        let app_hooks = hooks.get("app").unwrap();
        assert_eq!(app_hooks.post_start.len(), 2);
        assert_eq!(app_hooks.post_start[0].command, vec!["step1"]);
        assert_eq!(app_hooks.post_start[1].command, vec!["step2", "--flag"]);
        assert_eq!(app_hooks.pre_stop.len(), 2);
        assert_eq!(app_hooks.pre_stop[0].command, vec!["cleanup1"]);
        assert_eq!(app_hooks.pre_stop[1].command, vec!["cleanup2", "--force"]);
    }

    #[test]
    fn extract_hooks_no_services_key_returns_empty() {
        let yaml = r#"
version: "3"
networks:
  default:
"#;
        let mut value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let hooks = extract_lifecycle_hooks(&mut value).unwrap();
        assert!(hooks.is_empty());
    }

    #[test]
    fn to_service_fields_quotes_args_with_spaces_and_special_chars() {
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["echo".into(), "hello world".into(), "it's alive".into()],
                ..Default::default()
            }],
            pre_stop: vec![],
        };
        let (start_post, _stop) = hooks.to_service_fields("systemd-%N").unwrap();
        // shlex quotes args with spaces and uses double-quotes when the arg contains an apostrophe
        assert_eq!(
            start_post,
            vec!["podman exec 'systemd-%N' echo 'hello world' \"it's alive\""]
        );
    }

    #[test]
    fn to_service_fields_with_user() {
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["whoami".into()],
                user: Some("postgres".into()),
                ..Default::default()
            }],
            pre_stop: vec![],
        };
        let (start_post, _) = hooks.to_service_fields("mycontainer").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec --user postgres mycontainer whoami"]
        );
    }

    #[test]
    fn to_service_fields_with_privileged() {
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["id".into()],
                privileged: true,
                ..Default::default()
            }],
            pre_stop: vec![],
        };
        let (start_post, _) = hooks.to_service_fields("mycontainer").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec --privileged mycontainer id"]
        );
    }

    #[test]
    fn to_service_fields_with_working_dir() {
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["ls".into()],
                working_dir: Some("/app".into()),
                ..Default::default()
            }],
            pre_stop: vec![],
        };
        let (start_post, _) = hooks.to_service_fields("mycontainer").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec --workdir /app mycontainer ls"]
        );
    }

    #[test]
    fn to_service_fields_with_environment_list() {
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["env".into()],
                environment: Some(HookEnvironment::List(vec!["FOO=bar".into(), "BAZ=qux".into()])),
                ..Default::default()
            }],
            pre_stop: vec![],
        };
        let (start_post, _) = hooks.to_service_fields("mycontainer").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec --env 'FOO=bar' --env 'BAZ=qux' mycontainer env"]
        );
    }

    #[test]
    fn to_service_fields_with_environment_map() {
        let mut map = IndexMap::new();
        map.insert("FOO".to_string(), Some("bar".to_string()));
        map.insert("NO_VAL".to_string(), None);
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["env".into()],
                environment: Some(HookEnvironment::Map(map)),
                ..Default::default()
            }],
            pre_stop: vec![],
        };
        let (start_post, _) = hooks.to_service_fields("mycontainer").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec --env 'FOO=bar' --env NO_VAL mycontainer env"]
        );
    }

    #[test]
    fn to_service_fields_with_all_fields() {
        let mut map = IndexMap::new();
        map.insert("DEBUG".to_string(), Some("1".to_string()));
        let hooks = LifecycleHooks {
            post_start: vec![HookEntry {
                command: vec!["app".into(), "--check".into()],
                user: Some("appuser".into()),
                privileged: true,
                working_dir: Some("/workspace".into()),
                environment: Some(HookEnvironment::Map(map)),
            }],
            pre_stop: vec![],
        };
        let (start_post, _) = hooks.to_service_fields("mycontainer").unwrap();
        assert_eq!(
            start_post,
            vec!["podman exec --user appuser --privileged --workdir /workspace --env 'DEBUG=1' mycontainer app --check"]
        );
    }
}
