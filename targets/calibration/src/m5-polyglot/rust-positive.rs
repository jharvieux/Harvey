pub fn currency_symbol(code: &str) -> &'static str {
    match code {
        "USD" => "$",
        _ => todo!("support additional currencies"),
    }
}
