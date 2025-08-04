dotenvx python
===============

dotenvx for Python, and compatible with [python-dotenv](https://pypi.org/project/python-dotenv/) with APIs.

# Get started

> dotenvx-py is not available on PyPI, and you need to install it from source.


Run `uv add "dotenvx-py @ https://github.com/linux-china/dotenvx-py.git"`
or add the following to your `pyproject.toml` file:

```toml
dependencies = [
    "dotenvx-py",
]

[tool.uv.sources]
dotenvx-py = { git = "https://github.com/linux-china/dotenvx-py.git" }
```

Load dotenv file by calling `load_dotenv()` function.

```python
from dotenvx_py import load_dotenv

load_dotenv()
```

# References

* https://dotenvx.com/
* [python-dotenv](https://pypi.org/project/python-dotenv/)