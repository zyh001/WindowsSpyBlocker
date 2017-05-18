package wireshark

// Interface of network
type Interface struct {
	ID     int    `json:"id"`
	Device string `json:"device"`
	Name   string `json:"name"`
}

// Interfaces of network
type Interfaces []Interface

func (slice Interfaces) Len() int {
	return len(slice)
}

func (slice Interfaces) Less(i, j int) bool {
	return slice[i].ID < slice[j].ID
}

func (slice Interfaces) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
