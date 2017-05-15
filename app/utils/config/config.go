package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
)

const (
	NAME    = "WindowsSpyBlocker"
	VERSION = "4.0.0"
	PACKAGE = "github.com/crazy-max/WindowsSpyBlocker"
	URL     = "https://" + PACKAGE
)

var App AppConf
var Libs LibsConf

type Lib struct {
	Url        string `json:"url"`
	Checksum   string `json:"checksum"`
	Zip        string
	Path       string
	Executable string
}

type LibsConf struct {
	Logparser struct {
		Lib
	} `json:"logparser"`
	Sysmon struct {
		Lib
	} `json:"sysmon"`
	WiresharkPortable struct {
		Lib
	} `json:"wiresharkPortable"`
}

type AppConf struct {
	Debug     bool `json:"debug"`
	Proxifier struct {
		LogPath string `json:"logPath"`
	} `json:"proxifier"`
	Sysmon struct {
		EvtxPath string `json:"evtxPath"`
	} `json:"sysmon"`
	Wireshark struct {
		PcapngPath string `json:"pcapngPath"`
	} `json:"wireshark"`
	Exclude struct {
		Ips   []string `json:"ips"`
		Hosts []string `json:"hosts"`
		Orgs  []string `json:"orgs"`
	} `json:"exclude"`
}

func init() {
	var err error

	App, err = getAppCfg()
	if err != nil {
		print.QuitFatal(err)
	}

	Libs, err = getLibsCfg()
	if err != nil {
		print.QuitFatal(err)
	}
}

func getAppCfg() (AppConf, error) {
	var cfg AppConf
	cfgPath := path.Join(pathu.Current, "app.conf")

	// Create conf if not exists
	if _, err := os.Stat(cfgPath); err != nil {
		conf, err := bindata.Asset("app.conf")
		if err != nil {
			err = errors.New(fmt.Sprintf("Cannot load asset app.conf: %s", err.Error()))
			return cfg, err
		}
		err = ioutil.WriteFile(cfgPath, conf, 0644)
		if err != nil {
			err = errors.New(fmt.Sprintf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error()))
			return cfg, err
		}
	}

	// Load config
	raw, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		err = errors.New(fmt.Sprintf("Cannot read %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error()))
		return cfg, err
	}

	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		err = errors.New(fmt.Sprintf("Cannot unmarshall %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error()))
		return AppConf{}, err
	}

	return cfg, nil
}

func getLibsCfg() (LibsConf, error) {
	var cfg LibsConf
	cfgPath := path.Join(pathu.Current, "libs.conf")

	// Create conf if not exists
	if _, err := os.Stat(cfgPath); err != nil {
		conf, err := bindata.Asset("libs.conf")
		if err != nil {
			err = errors.New(fmt.Sprintf("Cannot load asset libs.conf: %s", err.Error()))
			return cfg, err
		}
		err = ioutil.WriteFile(cfgPath, conf, 0644)
		if err != nil {
			err = errors.New(fmt.Sprintf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error()))
			return cfg, err
		}
	}

	// Load config
	raw, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		err = errors.New(fmt.Sprintf("Cannot read %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error()))
		return cfg, err
	}

	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		err = errors.New(fmt.Sprintf("Cannot unmarshall %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error()))
		return LibsConf{}, err
	}

	return cfg, nil
}
