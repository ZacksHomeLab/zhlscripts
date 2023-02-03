# Purpose
This regular expression can be used for retrieving the first two words at the start of a line. This is useful for querying a service that may have an additional word as a parameter.

# Two-Words RegEx
```
^([(a-zA-Z)]+)([\s][a-zA-Z]([\w]*)+)?
```

# Matching Examples
```
Nginx
Nginx Full
Nginx-Full
```

# Non-Matching Examples
```
5Nginx
Nginx Full Test
Nginx 5
```
