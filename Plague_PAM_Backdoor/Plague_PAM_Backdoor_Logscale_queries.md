# Plague PAM-Based Backdoor - LogScale Queries

Queries below are copied from the dashboard YAML. Adjust allowlists and
paths to your environment as needed.

## Behavioral detection for PAM-based backdoor
```logscale
#event_simpleName="ProcessRollup2"
// Exclude package manager commands (yum, dnf-automatic, dnf) to ignore normal system updates
// 1) Exclude yum/dnf (with or without explicit /usr/bin or /bin path)
| not regex(field=CommandLine, regex="(?i)(?:^|\\s)(?:/usr/bin/|/bin/)?(?:yum|dnf)(?:\\s|$)")

// 2) Exclude dnf-automatic (+ path variant) and the helper tools (with or without a path)
| not regex(field=CommandLine, regex="(?i)(?:^|\\s)(?:(?:/usr/bin/|/bin/)?dnf-automatic|(?:[^\\s]*/)?(?:dnf_helper\\.py|oscs_extract))(?:\\s|$)")

// Exclude these container runtimes because they legitimately unpack image layers into their own overlay filesystems—writes under crio/runc/containerd/podman/buildah context aren’t touching the host’s real /usr/lib64/security.
| not regex(field=ImageFileName, regex="(?i)(?:^|/)(?:crio|runc|containerd|podman|buildah)$")
//| rawstring_PR2:=@rawstring
| join(
    {
        // Match any writes under /etc/pam.d/ or /lib64/security/ (case-insensitive)
        in(field=#event_simpleName, values=["FileDetectInfo","ELFFileWritten","CriticalFileModified"])
        //| regex(field=TargetFileName,regex="(?i)(?:^|/)(?:etc/pam\\.d|lib(?:64)?/security)/")
        // all including MacOS -> | (TargetFileName="/etc/pam.d/*" OR TargetFileName="/private/etc/pam.d/*" OR TargetFileName="/lib/security/*" OR TargetFileName="/lib64/security/*" OR TargetFileName="/usr/lib/security/*" OR TargetFileName="/usr/lib64/security/*" OR TargetFileName="/usr/lib/pam/*" OR TargetFileName="/private/usr/lib/pam/*")
        | (TargetFileName="/etc/pam.d/*" OR TargetFileName="/lib/security/*" OR TargetFileName="/lib64/security/*" OR TargetFileName="/usr/lib/security/*" OR TargetFileName="/usr/lib64/security/*") //only linux
        | rawstring_tf:=@rawstring
        | event_TF:=#event_simpleName
        | TargetFileName_TF:=TargetFileName
        }, field=[aid,TargetProcessId], key=[aid,ContextProcessId], include=[event_TF,TemplateDisposition,ContextProcessId,TargetFileName_TF,rawstring_tf],mode=inner, max=20000)
        | groupBy([#repo,ComputerName], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([CommandLine,ImageFileName,SHA256HashData,event_TF,TemplateDisposition,TargetFileName_TF,ContextProcessId,rawstring_tf], limit=20000)]))
        | FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
        | LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```

## Static hash detection for Plague PAM-based backdoor
```logscale
"85c66835657e3ee6a478a2e0b1fd3d87119bebadc43a16814c30eb94c53766bb"
or "7c3ada3f63a32f4727c62067d13e40bcb9aa9cbec8fb7e99a319931fc5a9332e" or "9445da674e59ef27624cd5c8ffa0bd6c837de0d90dd2857cf28b16a08fd7dba6"
or "5e6041374f5b1e6c05393ea28468a91c41c38dc6b5a5230795a61c2b60ed14bc" or "e594bca43ade76bbaab2592e9eabeb8dca8a72ed27afd5e26d857659ec173261"
or "6d2d30d5295ad99018146c8e67ea12f4aaa2ca1a170ad287a579876bf03c2950" or "14b0c90a2eff6b94b9c5160875fcf29aff15dcfdfd3402d953441d9b0dca8b39"
or "f62624d28aaa0de93e49fcdaaa3b73623723bdfb308e95dcbeab583bdfe3ac64" or "24d71c0524467db1b83e661abc2b80d582f62fa0ead38fdf4974a64d59423ff1"
or "5aeae90e3ab3418ef001cce2cddeaaaea5e4e27efdad4c6fa7459105ef6d55fa" or "ae26a4bc9323b7ae9d135ef3606339ee681a443ef45184c2553aa1468ba2e04b"
or "ac32ed04c0a81eb2a84f3737affe73f5101970cc3f07e5a2e34b239ab0918edd"
```

## Behavioral detection for PAM-based backdoor #2
```logscale
#event_simpleName="ProcessRollup2"
// Exclude package manager commands (yum, dnf-automatic, dnf) to ignore normal system updates
| (CommandLine != /\/usr\/bin\/(yum|dnf)(\s|$)/i or CommandLine != /\/bin\/(yum|dnf)(\s|$)/i or CommandLine != /(^|\s)dnf-automatic(\s|$)/i or CommandLine != /(^|\s)dnf_helper\.py(\s|$)/i or CommandLine != /(^|\s)oscs_extract(\s|$)/i)
// Exclude these container runtimes because they legitimately unpack image layers into their own overlay filesystems—writes under crio/runc/containerd/podman/buildah context aren’t touching the host’s real /usr/lib64/security.
| ImageFileName != /crio|dockerd|runc|containerd|podman|buildah/i

| rawstring_PR2:=@rawstring
| join({

// Match any writes under /etc/pam.d/ or /lib64/security/ (case-insensitive)
TargetFileName = /^\/(etc\/pam\.d\/|(usr\/)?lib(64)?\/security\/)/i

| not in(field=#event_simpleName, values=["FileOpenInfo","SharedObjectLoaded"])
| event_tf:=#event_simpleName
| rawstring_tf:=@rawstring
}, field=[aid,TargetProcessId], key=[aid,ContextProcessId], include=[event_tf,TemplateDisposition,rawstring_tf],mode=inner, max=20000)
| groupBy([#repo,ComputerName], function=([count(aid, as=EventsCount), min(timestamp, as=FirstEvent), max(timestamp, as=LastEvent), collect([CommandLine,ImageFileName,SHA256HashData,event_tf,TemplateDisposition,rawstring_tf,rawstring_PR2], limit=20000)]))
| FirstEvent:=formatTime(format="%F %T.%L", field="FirstEvent")
| LastEvent:=formatTime(format="%F %T.%L", field="LastEvent")
```
