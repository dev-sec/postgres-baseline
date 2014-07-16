# encoding: utf-8

require 'spec_helper'

ENV['posgresql_password'] = 'iloverandompasswordsbutthiswilldo'

RSpec.configure do |c|
  c.filter_run_excluding skipOn: backend(Serverspec::Commands::Base).check_os[:family]
end

RSpec::Matchers.define :match_key_value do |key, value|
  match do |actual|
    actual =~ /^\s*?#{key}\s*?=\s*?#{value}/
  end
end

# set OS-dependent filenames and paths
case backend.check_os[:family]
when 'Ubuntu'
  service_name = 'postgres'
when 'RedHat', 'Fedora'

  service_name = 'postgres'
end

describe service("#{service_name}") do
  it { should be_enabled }
  it { should be_running }
end
