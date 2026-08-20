def load_optional_value():
    try:
        return read_value()
    except LookupError as error:
        raise RuntimeError("value lookup failed") from error
