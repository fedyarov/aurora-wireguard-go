# Wireguard for AuroraOS

Fully-compatible with AuroraOS ConnMan VPN WireGuard plugin. Use wireguard-go as user-space protocol implementation. Needs to be signed with Extended profile.

## Package features
|Feature|Implemented|
|-------|-----------|
|ConnMan VPN Plugin|:white_check_mark:|
|Settings Plugin|:heavy_multiplication_x:|
|Desktop Application|:heavy_multiplication_x:|

## ConnMan VPN plugin features
|Feature|Implemented|
|-------|-----------|
|Multiple Peers|:white_check_mark:|
|Split Routing|:white_check_mark:|
|Configure with config file|:heavy_multiplication_x:|
|Configure with options|:white_check_mark:|
|On-air configuration|:heavy_multiplication_x:|

## Dependencies
1. connman-devel
2. glib-2.0
3. dbus-1

## How to build
1. Apply patches 

Apply patches `001-wireguard-go-Made-changes-to-be-compatible-with.patch` and `0001-tools-Made-changes-to-be-used-in-ConnMan-VPN-Wire.patch` to
`wireguard-go` and `wireguard-tools` respectively.

2. Build wireguard-go

wireguard-go used as user-space implementation of protocol. As it written in Golang, it can be compiled on host system without SDK for AuroraOS.
To build you need to configure GoLang with these env variables:
```
export GOARCH=arm
export GOARM=7
export GOOS=linux
```
Or `export GOARCH=arm64` for 64-bit AuroraOS.

Then build 
```
cd wireguard-go/
go build
```

3. Build rpm package and sign with **Extended** key

Build rpm package for AuroraOS in SDK or PSDK and sign with Extended key. 
Extended key is required because VPN application in AuroraOS needs Extended profile.

4. Copy package to your device and install it via APM.

## How to use

Currently the package doesn't have UI plugin for Settings or Desktop Application when wireguard can be configured. But it's still can be configured with D-Bus from terminal or another application with VPN permission or without VPN permission, but with the ssme orgname.

To configure it via D-Bus from terminal you can use script `script/create.sh` on device:
```
bash create.sh
```

Available options you can find in [aurora/wireguard.h](https://github.com/fedyarov/aurora-wireguard-go/blob/main/aurora/wireguard.h)

To modidy connection via D-Bus from terminal you can use script `script/modify.sh` on device:
```
bash modify.sh
```

*Note: To apply new options for Wireguard connection currently you need to restart Wireguard VPN connection*
