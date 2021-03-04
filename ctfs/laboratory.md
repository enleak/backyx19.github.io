**Tags:** `LFI` `Directory Traversal` `RCE` `GitLab` `Docker` `Linux` `SSL`

[Report](https://hackerone.com/reports/827052)

### Summary

- Alternate vhost from the nmap scan `ssl-cert: DNS:git.laboratory.htb`
- Login page on the `git.laboratory.htb` (**Gitlab**)
- Register and login as a test account (email: `test123@laboratory.htb`)
- Testing for local file inclusion (arbitrary file read) in the UploadsRewriter when moving an issue (Project 1 > Project 2)
- RCE present. `cookies_serializer` is set to `:hybrid` by default

**Confirming this:**

````
Rails.application.config.action_dispatch.use_cookies_with_metadata = true
Rails.application.config.action_dispatch.cookies_serializer =
  Gitlab::Utils.to_boolean(ENV['USE_UNSAFE_HYBRID_COOKIES']) ? :hybrid : :json

````

### Steps to accomplish RCE:

- **First:** Grab the secret_key_base from `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml` using the arbitrary file read
- **Second:** Use the `experimentation_subject_id=` cookie with a Marshalled payload
- **Third:** Create a Marshalled payload with the gitlab-rails console (local docker instance of gitlab 12.8.2)
    - [Gitlab docker installation doc](https://docs.gitlab.com/omnibus/docker/)
- **Fourth:** Change your own gitlab instance (via docker) `secret_key_base` to match 
- **Fifth:** Open a **gitlab-rails console** and run the following ruby script: 


.......
