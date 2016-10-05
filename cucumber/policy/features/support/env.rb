require 'aruba'
require 'aruba/cucumber'

$possum_url = ( ENV['CONJUR_APPLIANCE_URL'] || 'http://possum' )
$possum_account = ( ENV['CONJUR_ACCOUNT'] || 'cucumber' )
$policy_dir = if File.exists?("/run")
  "/run"
else
  File.expand_path('../../../../../run', __FILE__)
end

require 'simplecov'
SimpleCov.start

system *(%w(possum policy load cucumber ./run/empty.yml)) or raise "Failed to load policy: #{$?.exitstatus}"