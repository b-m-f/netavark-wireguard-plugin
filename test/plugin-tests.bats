#!/usr/bin/env bat
load helpers


# create config for plugin with the name as first arg
function get_config() {
    cat <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "plugin-net": {
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "plugin-net": {
         "name": "test",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "wireguard-plugin",
         "options": {
            "config": "$1"
         },
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false
      }
   }
}
EOF
}

function run_netavark_with_plugins() {
    run_netavark --plugin-directory $(pwd)/target/release/ "$@"
}

@test "wireguard setup truncates long interface name" {
    config=$(cat <<EOF
{
   "container_id": "someID",
   "container_name": "someName",
   "networks": {
      "plugin-net": {
         "interface_name": "eth0"
      }
   },
   "network_info": {
      "plugin-net": {
         "name": "testiswaytoolong",
         "id": "2f259bab93aaaaa2542ba43ef33eb990d0999ee1b9924b557b7be53c0b7a1bb9",
         "driver": "wireguard-plugin",
         "options": {
            "config": "./test/testfiles/wireguard.conf"
         },
         "ipv6_enabled": false,
         "internal": false,
         "dns_enabled": false
      }
   }
}
EOF
)
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    # check that interface exists
    run_in_container_netns ip a
    # full interface name is not used
    expected_rc=1
    run_in_container_netns ip -j --details link show wg-testiswaytoolong

    # the name is truncated to 12 chars and starts with wg-
    expected_rc=0
    run_in_container_netns ip -j --details link show wg-testiswaytoo
}

@test "wireguard setup works correctly" {
    config=$(get_config ./test/testfiles/wireguard.conf)

    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    interface_info="$output"
    assert_json "$interface_info" '.test.interfaces."wg-test.subnets"' "=="  "null" "Container interface is up"


    # check that interface exists
    run_in_container_netns ip -j --details link show wg-test
    link_info="$output"
    assert_json "$link_info" '.[].flags[] | select(.=="UP")' "=="  "UP" "Container interface is up"
    assert_json "$link_info" ".[].linkinfo.info_kind" "==" "wireguard" "Container interface is a macvlan device"

    # check ip addresses
    ipaddr="10.10.0.1/16"
    ipaddr2="10.11.1.1/32"
    run_in_container_netns ip addr show wg-test
    assert "$output" "=~" "$ipaddr" "WireGuard IPv4 address matches container address"
    assert "$output" "=~" "$ipaddr2" "IPv4 without CIDR was added to container WireGuard interface"

    # check gateway assignment
    run_in_container_netns ip r
    assert "$output" "=~" "10.10.0.0/16 dev wg-test proto kernel scope link src 10.10.0.1" "wireguard ipv4 gateways are correctly set up"
    assert "$output" "=~" "10.11.1.0/24 via 10.11.1.1 dev wg-test proto static metric 100" "wireguard ipv4 gateways are correctly set up"

    # check Interface key
    # To get the key that is compared here run echo $PRIVATE_KEY | wg pubkey on the PrivateKey from testfiles/wireguard.conf
    run_in_container_netns wg
    assert "$output" "=~" "private key: \(hidden\)" "WireGuard interface key was correctly set"
    assert "$output" "=~" "public key: HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=" "WireGuard interface key was correctly set"

    # check WireGuard Port
    assert "$output" "=~" "listening port: 51820" "WireGuard port was correctly set"

    # check IPv4 peer
    assert "$output" "=~" "peer: xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=" "WireGuard peer was added"
    assert "$output" "=~" "preshared key: \(hidden\)" "WireGuard peer preshared key was correctly set"
    assert "$output" "=~" "allowed ips: 10.10.0.2/32, 10.11.1.0/24" "WireGuard peer allowed IPs were correctly set"
    assert "$output" "=~" "endpoint: 123.45.67.89:12345" "WireGuard peer endpoint was correctly set"


    run_netavark_with_plugins teardown $(get_container_netns_path) <<<"$config"
    expected_rc=1
    run_in_container_netns ip -j --details link show wg-test
    link_info="$output"
    assert "$output" "=" "Device \"wg-test\" does not exist."
}
@test "WireGuard Address parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-address-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration Address on line 1.' "Correct error on empty address"
    
    expected_rc=1
    config=$(get_config ./test/testfiles/wireguard-fail-address-missing.conf)

    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'Interface is missing an Address' "Correct error on missing address"
}

@test "WireGuard AllowedIPs parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-ipv6.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard peers AllowedIPs:' "Correct error on wrong IPv6"
    
    config=$(get_config ./test/testfiles/wireguard-fail-ipv4.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard peers AllowedIPs:' "Correct error on wrong IPv4"
    
    config=$(get_config ./test/testfiles/wireguard-fail-allowedips-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration AllowedIPs on line 8.  No value provided' "Correct error on empty AllowedIPs"

    config=$(get_config ./test/testfiles/wireguard-fail-allowedips-missing.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'Peer #0 is missing AllowedIPs' "Correct error on missing AllowedIPs"
}

@test "WireGuard endpoint parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-endpoint-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration Endpoint on line 9.  No value provided' "Correct error on empty endpoint"
    
    config=$(get_config ./test/testfiles/wireguard-fail-endpoint-ip.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when trying to parse Endpoint 123.45.67.389:12345 for peer 0' "Correct error on wrong Endpoint IP"
    
    config=$(get_config ./test/testfiles/wireguard-fail-endpoint-port.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when trying to parse Endpoint 123.45.67.89:123456 for peer 0:' "Correct error on wrong Endpoint Port"
    
    config=$(get_config ./test/testfiles/wireguard-fail-endpoint-hostname.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when trying to parse Endpoint test.thisdomainshouldnotexist:12345 for peer 0:' "Correct error on wrong Endpoint hostname"
}

@test "WireGuard port parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-port-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration ListenPort on line 3.  No value provided.' "Correct error on empty port"
    
    config=$(get_config ./test/testfiles/wireguard-fail-port.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard interface port:' "Correct error on incorrect port"
}

@test "WireGuard private key parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-privatekey-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration PrivateKey on line 4.  No value provided.' "Correct error on empty privatekey"
    
    config=$(get_config ./test/testfiles/wireguard-fail-privatekey-missing.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'Interface is missing a PrivateKey' "Correct error on missing privatekey"
    
    config=$(get_config ./test/testfiles/wireguard-fail-privatekey.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when decoding base64 PrivateKey:' "Correct error on incorrect privatekey"
}

@test "WireGuard public key parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-publickey-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration PublicKey on line 7.  No value provided.' "Correct error on empty publickey"
    
    config=$(get_config ./test/testfiles/wireguard-fail-publickey-missing.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'invalid WireGuard configuration: Peer #0 is missing a PublicKey' "Correct error on missing publickey"
    
    config=$(get_config ./test/testfiles/wireguard-fail-publickey.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when decoding base64 PublicKey:' "Correct error on incorrect publickey"
}

@test "WireGuard preshared key parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-presharedkey-empty.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration PresharedKey on line 8.  No value provided.' "Correct error on empty presharedkey"
    
    config=$(get_config ./test/testfiles/wireguard-fail-presharedkey.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when decoding base64 PresharedKey:' "Correct error on incorrect presharedkey"
}

@test "WireGuard incorrect line parsing fail" {
    config=$(get_config ./test/testfiles/wireguard-fail-broken-line.conf)

    expected_rc=1
    run_netavark_with_plugins setup $(get_container_netns_path) <<<"$config"
    result="$output"

    assert "$output" "=~" 'when parsing WireGuard configuration Address on line: 1'
}
