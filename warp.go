package libXray

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"

	"github.com/GFW-knocker/Xray-core/infra/conf"
	"github.com/xtls/libxray/warp"
	"github.com/xtls/libxray/ws"
	// "github.com/sagernet/sing-box/option"
)

func WarpSetupFree() error {
	// make primary identity
	license := "notset"
	_license := ""
	warp.UpdatePath("./warp-primary")
	if !warp.CheckProfileExists(license) {
		err := warp.LoadOrCreateIdentity(_license)
		if err != nil {
			log.Printf("error: %v", err)
			return fmt.Errorf("error: %v", err)
		}
	}
	// make secondary identity
	warp.UpdatePath("./warp-secondary")
	if !warp.CheckProfileExists(license) {
		err := warp.LoadOrCreateIdentity(_license)
		if err != nil {
			log.Printf("error: %v", err)
			return fmt.Errorf("error: %v", err)
		}
	}
	return nil
}

func convertConfig(device *ws.DeviceConfig) (*conf.WireGuardConfig, error) {
	peers := []*conf.WireGuardPeerConfig{}
	for _, peer := range device.Peers {
		ips := []string{}
		for _, allowedIP := range peer.AllowedIPs {
			ips = append(ips, allowedIP.String())
		}
		peers = append(peers, &conf.WireGuardPeerConfig{
			KeepAlive:    0,
			AllowedIPs:   ips,
			PublicKey:    peer.PublicKey,
			PreSharedKey: peer.PreSharedKey,
			Endpoint:     *peer.Endpoint,
		})
	}

	kmode := false
	endpoints := []string{}
	for _, endpoint := range device.Endpoint {
		endpoints = append(endpoints, endpoint.String())
	}
	return &conf.WireGuardConfig{
		IsClient:   true,
		KernelMode: &kmode,

		MTU:            int32(device.MTU),
		SecretKey:      device.SecretKey,
		Peers:          peers,
		NumWorkers:     int32(runtime.NumCPU()),
		Address:        endpoints,
		DomainStrategy: "ForceIP",
		Reserved:       []byte{},
	}, nil
}

func WarpGetOutbounds(tag string, endpoint string, nested bool) (string, error) {
	options := []conf.OutboundDetourConfig{}
	primaryTag := tag
	if nested {
		primaryTag = "primary"
		config, err := ws.ParseConfig("./warp-secondary/wgcf-profile.ini", endpoint)
		if err != nil {
			return "", err
		}
		wgOptions, err := convertConfig(config.Device)
		if err != nil {
			return "", err
		}
		rawWgOptions, err := json.Marshal(wgOptions)
		if err != nil {
			return "", err
		}
		rawMsg := json.RawMessage(rawWgOptions)
		options = append(options, conf.OutboundDetourConfig{
			Protocol:    "wireguard",
			SendThrough: nil,
			Tag:         tag,
			Settings:    &rawMsg,
			StreamSetting: &conf.StreamConfig{
				SocketSettings: &conf.SocketConfig{
					DialerProxy: primaryTag,
				},
			},
			ProxySettings: nil,
			MuxSettings:   nil,
		})
	}
	config, err := ws.ParseConfig("./warp-primary/wgcf-profile.ini", endpoint)
	if err != nil {
		return "", err
	}
	wgOptions, err := convertConfig(config.Device)
	if err != nil {
		return "", err
	}
	rawWgOptions, err := json.Marshal(wgOptions)
	if err != nil {
		return "", err
	}
	rawMsg := json.RawMessage(rawWgOptions)
	options = append(options, conf.OutboundDetourConfig{
		Protocol:      "wireguard",
		SendThrough:   nil,
		Tag:           primaryTag,
		Settings:      &rawMsg,
		StreamSetting: nil,
		ProxySettings: nil,
		MuxSettings:   nil,
	})
	jsonData, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
