# FQDN RegEx

```
^(?=.{1,255}$)([a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$
```

## Matching Examples

```
test.com
example.domain.co.uk
ad.example.domain.com
```

## Non-Matching Examples

```
ad.example.123
ad.example.c
ad.example.
```