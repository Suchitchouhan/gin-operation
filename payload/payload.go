package payload

type SendBook struct {
	ID          uint   `json:"id"`
	Name        string `json:"Name"`
	Image       string `json:"image"`
	Description string `json:"Description"`
	Account_ID  uint
}
