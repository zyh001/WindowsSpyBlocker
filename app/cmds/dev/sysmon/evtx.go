package sysmon

type Evtx struct {
	Event Eventx `json:"Event"`
}

type Eventx struct {
	EventData EvtxData `json:"EventData"`
}

type EvtxData struct {
	DestinationHostname string `json:"DestinationHostname"`
	DestinationIp       string `json:"DestinationIp"`
	DestinationIsIpv6   string `json:"DestinationIsIpv6"`
	DestinationPort     string `json:"DestinationPort"`
	DestinationPortName string `json:"DestinationPortName"`
	Image               string `json:"Image"`
	Initiated           string `json:"Initiated"`
	ProcessGuid         string `json:"ProcessGuid"`
	ProcessId           string `json:"ProcessId"`
	Protocol            string `json:"Protocol"`
	SourceHostname      string `json:"SourceHostname"`
	SourceIp            string `json:"SourceIp"`
	SourceIsIpv6        string `json:"SourceIsIpv6"`
	SourcePort          string `json:"SourcePort"`
	SourcePortName      string `json:"SourcePortName"`
	User                string `json:"User"`
	UtcTime             string `json:"UtcTime"`
}
