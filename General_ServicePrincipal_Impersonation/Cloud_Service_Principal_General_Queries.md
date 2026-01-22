# Cloud Service Principal General Queries

Adjust field names as needed. Assumes fields like PrincipalType, PrincipalName, ClientIp, UserAgent,
RequestAction, ServiceName, Region, CompartmentName, AuthType, CredentialId. If you already tag SPs,
filter with that tag instead of the regex below.

## All SP activity by SP
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi", strict=false)
| groupBy(PrincipalName, function=count()) | sort(count, desc)
```

## Top actions per SP
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi", strict=false)
| groupBy(PrincipalName, RequestAction, function=count()) | sort(count, desc)
```

## New IPs per SP - Last 7d
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi") |
groupBy(PrincipalName, ClientIp, function=count()) | sort(count, desc)
```

## New IPs per SP - Prev 30d excl last 7d
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi") |
groupBy(PrincipalName, ClientIp, function=count()) | sort(count, desc)
```

## IAM/credential-adjacent actions by SP
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi") |
regex(field=RequestAction, regex="(Create|Update|Delete)(Auth|Secret|Key|Policy|
Role|App|Credential|Certificate)", flags="Fi", strict=false)
```

## First-time API families/services per SP
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi") |
groupBy(PrincipalName, ServiceName, function=count()) | sort(count, desc)
```

## New regions/compartments per SP
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi") |
groupBy(PrincipalName, Region, CompartmentName, function=count()) | sort(count,
desc)
```

## IdP app changes for any SP (if ingested)
```logscale
| regex(field=EventCategory, regex="(Application|App Registration|Service
Principal)", flags="Fi") | regex(field=EventName, regex="(Client
Secret|Credential|Certificate|App Updated|Grant Issued|Key Added)", flags="Fi")
```

## Auth method / credential ID shifts per SP
```logscale
| regex(field=PrincipalType,
regex="(serviceprincipal|application|serviceaccount)", flags="Fi") |
groupBy(PrincipalName, AuthType, CredentialId, function=count()) | sort(count,
desc)
```
