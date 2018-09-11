# name: Slack Oauth2 Discourse (JL)
# about: This plugin allows your users to sign up/in using their Slack account.
# version: 0.3
# authors: Daniel Climent
# url: https://github.com/jcmrgo/oauth-slack-discourse

require 'auth/oauth2_authenticator'
require 'omniauth-oauth2'

class SlackAuthenticator < ::Auth::OAuth2Authenticator
  
  CLIENT_ID = ENV['SLACK_CLIENT_ID']
  CLIENT_SECRET = ENV['SLACK_CLIENT_SECRET']
  TEAM_ID = ENV['SLACK_TEAM_ID']
  
  def name
    'slack'
  end
  
  def after_authenticate(auth_token)
    result = Auth::Result.new
    
    # Grab the info we need from OmniAuth
    data = auth_token[:info]
    
    provider = auth_token[:provider]
    slack_uid = auth_token["uid"]
    
    result.name = data[:name]
    result.username = data[:nickname]
    result.email = data[:email]
    
    result.email_valid = true
    result.extra_data = { uid: slack_uid, provider: provider }
    
    current_info = ::PluginStore.get("slack", "slack_uid_#{slack_uid}")
    
    if User.find_by_email(data[:email]).nil?
      user = User.create(name: data[:name], email: data[:email], username: data[:nickname], approved: true)
      ::PluginStore.set("slack", "slack_uid_#{slack_uid}",{user_id: user.id})
    end
    
    result.user =
        if current_info
          User.where(id: current_info[:user_id]).first
        elsif user = User.where(username: result.username).first
          user
        end
    result.user ||= User.where(email: data[:email]).first
    
    result
  end
  
  def after_create_account(user, auth)
    data = auth[:extra_data]
    user.update_attribute(:approved, true)
    ::PluginStore.set("slack", "slack_uid_#{data[:uid]}", {user_id: user.id})
  end
  
  def register_middleware(omniauth)
    unless TEAM_ID.nil?
     omniauth.provider :slack, CLIENT_ID, CLIENT_SECRET, scope: 'identity.basic, identity.email, identity.team, identity.avatar', team: TEAM_ID
     omniauth.provider :slack, CLIENT_ID, CLIENT_SECRET, scope: 'identify, team:read, users:read, users:read.email', team: TEAM_ID
    else
     omniauth.provider :slack, CLIENT_ID, CLIENT_SECRET, scope: 'identify, team:read, users:read, users:read.email', team: TEAM_ID
    end
  end
end

class OmniAuth::Strategies::Slack < OmniAuth::Strategies::OAuth2
  # Give your strategy a name.
  include OmniAuth::Strategy
  
  TEAM_ID = ENV['SLACK_TEAM_ID']
  
  option :name, "slack"
  
  option :provider_ignores_state, true
  
  option :team, TEAM_ID
  
  option :authorize_options, [ :scope, :team ]
  
  option :client_options, {
      site: "https://slack.com",
      token_url: "/api/oauth.access"
  }
  
  option :auth_token_params, {
      mode: :query,
      param_name: 'token'
  }
  
  uid { raw_info['user_id'] }
  
  info do
    {
        name: user_info['user']['profile']['real_name_normalized'],
        email: user_info['user']['profile']['email'],
        nickname: user_info['user']['name']
    }
  end
  
  extra do
    { raw_info: raw_info, user_info: user_info }
  end

        def callback_phase # rubocop:disable AbcSize, CyclomaticComplexity, MethodLength, PerceivedComplexity
          error = request.params["error_reason"] || request.params["error"]
          if error
            fail!(error, CallbackError.new(request.params["error"], request.params["error_description"] || request.params["error_reason"], request.params["error_uri"]))
          elsif !options.provider_ignores_state && (request.params["state"].to_s.empty? || request.params["state"] != session.delete("omniauth.state"))
            fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
          else
            self.access_token = build_access_token
            Rails.logger.info ">> #{ user_info }"
            Rails.logger.info ">> #{ raw_info }"
            ac = access_token.get("/api/users.identity").parsed
            Rails.logger.info ">> #{ac}"
            Rails.logger.info ">> #{ac['team']}"
            Rails.logger.info ">> #{ac['team'].try(:[], 'id').to_s}"
            Rails.logger.info ">> #{TEAM_ID}"
            Rails.logger.info ">> #{(ac['team'].try(:[], 'id').to_s == TEAM_ID.to_s)}"
            
            if ac && (ac['team'].try(:[], 'id').to_s != TEAM_ID.to_s)
              Rails.logger.info ">> #{ac}"
              fail!(:invalid_team, CallbackError.new('error_message', 'error_message', '/auth/failure'))
            else
              self.access_token = access_token.refresh! if access_token.expired?
              m = OmniAuth::Strategy.instance_method(:callback_phase).bind(self)
              m.call
            end
          end
        rescue ::OAuth2::Error, CallbackError => e
          fail!(:invalid_credentials, e)
        rescue ::Timeout::Error, ::Errno::ETIMEDOUT => e
          fail!(:timeout, e)
        rescue ::SocketError => e
          fail!(:failed_to_connect, e)
        end

  def user_info
    @user_info ||= access_token.get("/api/users.info?user=#{raw_info['user_id']}").parsed
  end
  
  def raw_info
    @raw_info ||= access_token.get("/api/auth.test").parsed
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