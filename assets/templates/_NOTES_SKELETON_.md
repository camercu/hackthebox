<%* let ip = tp.config.target_file.parent.name; _%>
---
ip: "<% ip %>"
hostname: "HOSTNAME"
fqdn: "hostname.oscp.exam"
---
# <% ip %> (<% "<\% tp.frontmatter.hostname %\>" %>)
<% "<\% tp.file.rename(tp.frontmatter.hostname) %\>" -%>

Tags: 

## scan

### nmap

```sh
sudo rustscan -a <% ip %> -- -T4 -sV -sC -oA tcp-all
```

```
OUTPUT
```


## access

TODO


## privesc

TODO


## proof

[//]: # (INSERT PROOF TEMPLATE(S) HERE)