# Netavark plugin for WireGuard networks

Using this plugin it is possible to spawn your podman containers into a WireGuard network.

## Installation
Download the binary from the release page and place it into your [netavark plugin directory](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html#driver-d-driver).

## Usage

### From Podman
1. Create a new network and provide the path to a [WireGuard config](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8). Example: `podman network create -d netavark-wireguard-plugin --interface-name=dummy --opt=config=/tmp/wireguard.conf wg`
2. Spawn the container into the network. Example: ``
3. The container should be connected and ready

Note that each container spawned into a network will reuse the same configuration file.
Use multiple different networks if you want to use different config files.

### Direct
Call netavark with `--plugin-directory $PATH_TO_PLUGIN_DIRECTORY` along with a path to a WireGuard configuration file passed via the options object. See [here](https://github.com/containers/netavark/blob/main/plugin-API.md) for more information.
