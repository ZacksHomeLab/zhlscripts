# FQDN RegEx

```
^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$
```

## Matching Examples

```
test.com
example.domain.co.uk
ad.example.domain.com
```

## Non-Matching Examples

```
ad.example.c
ad.example.
```
