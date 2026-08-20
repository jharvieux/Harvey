pub fn currency_symbol(code: &str) -> Result<&'static str, String> {
    match code {
        "USD" => Ok("$"),
        _ => Err(format!("unsupported currency: {code}")),
    }
}
