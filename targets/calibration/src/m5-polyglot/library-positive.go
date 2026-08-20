package ledger

func RequiredCurrency(code string) string {
	if code == "" {
		panic("currency code is required")
	}
	return code
}
