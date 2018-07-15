require File.expand_path('../boot', __FILE__)

require 'rails/all'

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module IdpMock
  class Application < Rails::Application
    # Settings in config/environments/* take precedence over those specified here.
    # Application configuration should go into files in config/initializers
    # -- all .rb files in that directory are automatically loaded.

    # Set Time.zone default to the specified zone and make Active Record auto-convert to this zone.
    # Run "rake -D time" for a list of tasks for finding time zone names. Default is UTC.
    # config.time_zone = 'Central Time (US & Canada)'

    # The default locale is :en and all translations from config/locales/*.rb,yml are auto loaded.
    # config.i18n.load_path += Dir[Rails.root.join('my', 'locales', '*.{rb,yml}').to_s]
    # config.i18n.default_locale = :de

    # Do not swallow errors in after_commit/after_rollback callbacks.

# STDOUT logging for Rails 4
# For Rails 5 see https://github.com/heroku/rails_12factor#rails-5-and-beyond
  if ENV["RAILS_LOG_TO_STDOUT"].present?
    log_level = ([(ENV['LOG_LEVEL'] || ::Rails.application.config.log_level).to_s.upcase, "INFO"] & %w[DEBUG INFO WARN ERROR FATAL UNKNOWN]).compact.first
    logger       = ::ActiveSupport::Logger.new(STDOUT)
    logger.formatter = proc do |severity, datetime, progname, msg|
      "#{datetime} #{severity}: #{String === msg ? msg : msg.inspect}\n"
    end
    logger       = ActiveSupport::TaggedLogging.new(logger) if defined?(ActiveSupport::TaggedLogging)
    logger.level = ::ActiveSupport::Logger.const_get(log_level)
    config.logger = logger

    STDOUT.sync = true
  end
    config.active_record.raise_in_transactional_callbacks = true
  end
end
