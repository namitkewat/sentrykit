# The `sentrykit` package

Everything listed in `sentrykit.__all__` is a re-export of a name that is defined — and
documented — in one of the modules under [core](core.md), [policy](policy.md) or
[stores](stores.md). Importing from the top level is the shorter spelling of the same object,
never a different one, so `from sentrykit import protect` and
`from sentrykit.decorator import protect` are interchangeable.

`sentrykit.__version__` carries the release, and it is the same string the distribution
metadata reports.

```{eval-rst}
.. automodule:: sentrykit
   :no-members:
```
