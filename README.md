# Netavark plugin for WireGuard networks

Using this plugin it is possible to spawn your podman containers into a WireGuard network.

## Installation
Download the binary from the release page and place it into your [netavark plugin directory](https://docs.podman.io/en/latest/markdown/podman-network-create.1.html#driver-d-driver).

## Usage

### From Podman
1. Create a new network and provide the path to a [WireGuard config](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8). Example: `podman network create -d netavark-wireguard-plugin --opt=config=/tmp/wireguard.conf wg`
2. Spawn the container into the network. Example: `podman run -ti --rm --network=wg test-image /bin/bash`
3. The container should be connected and ready

Note that each container spawned into a network will reuse the same configuration file.
Use multiple different networks if you want to use different config files.

### Direct
Call netavark with `--plugin-directory $PATH_TO_PLUGIN_DIRECTORY` along with a path to a WireGuard configuration file passed via the options object. See [here](https://github.com/containers/netavark/blob/main/plugin-API.md) for more information.

# Important things to know

- Only the most important fields of a `wg-quick` config file are supported. Please check [this example](./test/testfiles/wireguard.conf) for a complete overview.
- IPv6 is currently **NOT SUPPORTED**. Routing is the main problem. Switching to [neli](https://github.com/jbaublitz/neli) might help.

- For the same reason you should make sure to double check the routing you set up for IPv4 as well.
- If you want DNS to work for your container you must set your DNS to be a server that is reachable via the WireGuard network.
- The container must initialize the first traffic. `PersistentKeepalive` is not supported.
