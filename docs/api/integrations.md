# Integrations

One decorator, N context providers. Each module below lives behind an optional extra and is
imported by nothing in the core; the shared halves — identity resolution, refusal rendering,
tool-manifest filtering — are in `base` and `tools` so a FastAPI refusal and a Flask refusal
are the same refusal. See [web frameworks](../web-frameworks.md) and [agents](../agents.md).

## `sentrykit.integrations.base`

```{eval-rst}
.. automodule:: sentrykit.integrations.base
   :members:
   :show-inheritance:
```

## `sentrykit.integrations.tools`

```{eval-rst}
.. automodule:: sentrykit.integrations.tools
   :members:
   :show-inheritance:
```

## `sentrykit.integrations.fastapi`

```{eval-rst}
.. automodule:: sentrykit.integrations.fastapi
   :members:
   :show-inheritance:
```

## `sentrykit.integrations.flask`

```{eval-rst}
.. automodule:: sentrykit.integrations.flask
   :members:
   :show-inheritance:
```

## `sentrykit.integrations.mcp`

```{eval-rst}
.. automodule:: sentrykit.integrations.mcp
   :members:
   :show-inheritance:
```

## `sentrykit.integrations.pydantic_ai`

```{eval-rst}
.. automodule:: sentrykit.integrations.pydantic_ai
   :members:
   :show-inheritance:
```
