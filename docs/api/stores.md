# Stores

Three contracts — policy source, grant store, audit sink — and the reference backends that
implement them. A third-party backend registers through the same entry-point groups and is
indistinguishable from the ones below; see [plugins](../plugins.md).

## `sentrykit.stores`

The package re-exports every contract and every shipped backend. The contracts are imported
eagerly; the backends resolve through a module-level `__getattr__` on first access, so
`from sentrykit.stores import JsonlAuditSink` imports exactly the one module it needs and no
import cycle is created.

```{eval-rst}
.. automodule:: sentrykit.stores
   :no-members:
```

## `sentrykit.stores.base`

```{eval-rst}
.. automodule:: sentrykit.stores.base
   :members:
   :show-inheritance:
```

## `sentrykit.stores.filesystem`

```{eval-rst}
.. automodule:: sentrykit.stores.filesystem
   :members:
   :show-inheritance:
```

## `sentrykit.stores.jsonfile`

```{eval-rst}
.. automodule:: sentrykit.stores.jsonfile
   :members:
   :show-inheritance:
```

## `sentrykit.stores.jsonl`

```{eval-rst}
.. automodule:: sentrykit.stores.jsonl
   :members:
   :show-inheritance:
```

## `sentrykit.stores.memory`

```{eval-rst}
.. automodule:: sentrykit.stores.memory
   :members:
   :show-inheritance:
```

## `sentrykit.stores.composite`

```{eval-rst}
.. automodule:: sentrykit.stores.composite
   :members:
   :show-inheritance:
```
