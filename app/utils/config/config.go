package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/crazy-max/WindowsSpyBlocker/app/bindata"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/pathu"
	"github.com/crazy-max/WindowsSpyBlocker/app/utils/print"
)

// App constants
const (
	NAME    = "WindowsSpyBlocker"
	VERSION = "4.0.0"
	PACKAGE = "github.com/crazy-max/WindowsSpyBlocker"
	URL     = "https://" + PACKAGE
)

// Config
var (
	App  appConf
	Libs libsConf
)

// Lib structure
type Lib struct {
	Url        string `json:"url"`
	Checksum   string `json:"checksum"`
	Zip        string
	Path       string
	Executable string
}

type appConf struct {
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

type libsConf struct {
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

func getAppCfg() (appConf, error) {
	var cfg appConf
	cfgPath := path.Join(pathu.Current, "app.conf")

	// Load default config
	defaultConf, err := bindata.Asset("app.conf")
	if err != nil {
		err = fmt.Errorf("Cannot load asset app.conf: %s", err.Error())
		return cfg, err
	}
	err = json.Unmarshal(defaultConf, &cfg)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall defaultConf: %s", err.Error())
		return appConf{}, err
	}

	// Create conf if not exists
	if _, err := os.Stat(cfgPath); err != nil {
		err = ioutil.WriteFile(cfgPath, defaultConf, 0644)
		if err != nil {
			err = fmt.Errorf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
			return cfg, err
		}
	}

	// Load config
	raw, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		err = fmt.Errorf("Cannot read %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		return cfg, err
	}
	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		return appConf{}, err
	}

	// Write config
	cfgJson, _ := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		err = fmt.Errorf("Cannot marshal config: %s", err.Error())
		return appConf{}, err
	}
	err = ioutil.WriteFile(cfgPath, cfgJson, 0644)
	if err != nil {
		err = fmt.Errorf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		return cfg, err
	}

	return cfg, nil
}

func getLibsCfg() (libsConf, error) {
	var cfg libsConf
	cfgPath := path.Join(pathu.Current, "libs.conf")

	// Create conf if not exists
	if _, err := os.Stat(cfgPath); err != nil {
		conf, err := bindata.Asset("libs.conf")
		if err != nil {
			err = fmt.Errorf("Cannot load asset libs.conf: %s", err.Error())
			return cfg, err
		}
		err = ioutil.WriteFile(cfgPath, conf, 0644)
		if err != nil {
			err = fmt.Errorf("Cannot write file %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
			return cfg, err
		}
	}

	// Load config
	raw, err := ioutil.ReadFile(cfgPath)
	if err != nil {
		err = fmt.Errorf("Cannot read %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		return cfg, err
	}

	err = json.Unmarshal(raw, &cfg)
	if err != nil {
		err = fmt.Errorf("Cannot unmarshall %s: %s", strings.TrimLeft(cfgPath, pathu.Current), err.Error())
		return libsConf{}, err
	}

	return cfg, nil
}
