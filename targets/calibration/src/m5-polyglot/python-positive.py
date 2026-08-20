def load_optional_value():
    try:
        return read_value()
    except LookupError:
        pass
