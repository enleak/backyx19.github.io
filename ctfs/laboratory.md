**Tags:** `LFI` `Directory Traversal` `RCE` `GitLab` `Docker` `Linux` `SSL`

[Report](https://hackerone.com/reports/827052)

## Summary

- Alternate vhost from the nmap scan `ssl-cert: DNS:git.laboratory.htb`
- Login page on the `git.laboratory.htb` (**Gitlab**)
- Register and login as a test account (email: `test123@laboratory.htb`)
- Testing for local file inclusion in the UploadsRewriter when moving an issue (Project 1 > Project 2)
- RCE present. `cookies_serializer` is set to `:hybrid` by default

Confirming this:

````
Rails.application.config.action_dispatch.use_cookies_with_metadata = true
Rails.application.config.action_dispatch.cookies_serializer =
  Gitlab::Utils.to_boolean(ENV['USE_UNSAFE_HYBRID_COOKIES']) ? :hybrid : :json

````


- 
- 
- 
- Creating a Marshalled payload with the gitlab-rails console
    RCE in the gitlab via experimentation_subject_id cookie
    Get an initial shell in a docker
    Resting user dexter password and login as him on gitlab
    got the ssh private keys from a project-repo
    Login as dexter
    Got user.txt
    Running LinEnum.sh and got a suid docker-security
    Running the binary
    Opening the binary uisng radare2 and analyaing the main
    The binary is using chmod withput specifying the full path
    Making a bash script name chmod and then exporting $PATH variable to the script directory
    path-hijacking and shell got shell as root
    got root.txt
