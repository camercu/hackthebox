### smb

```sh
# get OS, hostname, and domain info, as well as signing (for relay attacks)
# also check null session
crackmapexec smb <% tp.frontmatter.hostname %> -u '' -p ''

# check guest account
crackmapexec smb <% tp.frontmatter.hostname %> -u 'guest' -p ''

# list shares
smbmap -H <% tp.frontmatter.ip %> -u 'guest' -p ''

# deeper scan 
enum4linux -u 'guest' -aMld <% tp.frontmatter.hostname %> | tee enum4linux.txt

# interact with SMB to view share
smbclient //<% tp.frontmatter.hostname %>/SHARENAME -U 'guest'

# list users
crackmapexec smb <% tp.frontmatter.hostname %> -u '' -p '' --users

# check password policy
crackmapexec smb <% tp.frontmatter.hostname %> -u '' -p '' --pass-pol
```