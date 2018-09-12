# oauth-slack-discourse
_________

**Slack API Oauth2 for Discourse- fixed fork :)**

Installation Instructions (for Docker installations): 

* Register a new Slack API application at: https://api.slack.com/applications/new if you haven't already
  * For the Redirect URL: http(s)://example.com/auth/slack/callback
* Open your container app.yml
* Under section ```hooks``` add the follow line:
```
          - git clone https://github.com/4xposed/oauth-slack-discourse.git
```
* Rebuild the docker container

```
./launcher rebuild my_image
```
* Configure in admin
