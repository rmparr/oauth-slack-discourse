# name: Slack Oauth2 Discourse (JL)
# about: This plugin allows your users to sign up/in using their Slack account.
# version: 0.3
# authors: Daniel Climent
# url: https://github.com/jcmrgo/oauth-slack-discourse

require 'auth/oauth2_authenticator'
gem 'ginjo-omniauth-slack', '2.4.0'

enabled_site_setting :slack_auth_enabled

class SlackAuthenticator < ::Auth::OAuth2Authenticator
  PLUGIN_NAME = 'oauth-slack'

  def name
    'slack'
  end

  def after_authenticate(auth_token)
    result = super

    if result.user && result.email && (result.user.email != result.email)
      begin
        result.user.primary_email.update!(email: result.email)
      rescue
        used_by = User.find_by_email(result.email)&.username
        Rails.loger.warn("FAILED to update email for #{user.username} to #{result.email} cause it is in use by #{used_by}")
      end
    end

    result
  end

  def register_middleware(omniauth)
    
    unless TEAM_ID.nil?
     omniauth.provider :slack, SiteSetting.slack_auth_client_id, SiteSetting.slack_auth_secret, scope: 'identity.basic, identity.email, identity.team, identity:read:user, team:read'
    else
     omniauth.provider :slack, SiteSetting.slack_auth_client_id, SiteSetting.slack_auth_secret, scope: 'identity.basic, identity.email, identity.team, identity:read:user, team:read', team: SiteSetting.slack_auth_team_id
    end
  end

  def enabled?
    SiteSetting.slack_auth_enabled
  end
end

auth_provider title: 'with Slack',
              message: 'Log in using your Slack account. (Make sure your popup blocker is disabled.)',
              frame_width: 920,
              frame_height: 800,
              authenticator: SlackAuthenticator.new('slack', trusted: true)

register_css <<CSS

  .btn-social.slack {
    background: #ab9ba9;
  }

  .btn-social.slack:before {
    content: "\\f198";
  }

CSS
