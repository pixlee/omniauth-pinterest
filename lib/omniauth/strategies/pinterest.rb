require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        :site => 'https://www.pinterest.com/',
        :authorize_url => 'https://www.pinterest.com/oauth/',
        :token_url => 'https://api.pinterest.com/v3/oauth/access_token/'
      }

      def request_phase
        options[:scope] ||= 'read_pins'
        options[:response_type] ||= 'code'
        super
      end

      uid { raw_info['id'] }

      info { raw_info }
      
      def callback_url
        full_host + script_name + callback_path
      end

      def authorize_params
        super.tap do |params|
          %w[redirect_uri].each do |v| 
            params[:redirect_uri] = request.params[v] if request.params[v]
          end 
        end 
      end 

      def raw_info
        @raw_info = access_token
      end

      def ssl?
        true
      end

    end
  end
end
