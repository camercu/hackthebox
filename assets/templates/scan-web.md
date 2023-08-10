### web

Running `gobuster` to enumerate web directories:

```sh
# directory discovery
ulimit -n 8192 # prevent file access error during scanning
gobuster dir -w /mnt/share/cheat/wordlists/webbust.txt -ezqrkt 100 -o gobuster.txt -u http://<% tp.frontmatter.hostname %>
```

Running `whatweb` to check web technologies in use:

```sh
# enumerate version info of tech stack, find emails, domains, etc.
whatweb -v -a3 --log-verbose whatweb.txt <% tp.frontmatter.hostname %>
```

Running `nikto` to check for common vulnerabilities:

```sh
nikto -o nikto.txt --maxtime=300s -C all -h <% tp.frontmatter.hostname %>
```