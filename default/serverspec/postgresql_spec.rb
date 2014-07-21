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
  service_name = 'postgresql'
  postgres_home = '/var/lib/postgresql'
  user_name = 'postgres'
when 'RedHat', 'Fedora'
  service_name = 'postgres'
end

describe service("#{service_name}") do
  it { should be_enabled }
  it { should be_running }
end

# find configfiles
# even better: psql -t -d postgres -P format=unaligned -c "show hba_file"
ret = backend.run_command("ls /etc/postgresql")
postgres_version = ret[:stdout].chomp
hba_config_file = "/etc/postgresql/#{postgres_version}/main/pg_hba.conf"
postgres_config_file = "/etc/postgresql/#{postgres_version}/main/postgresql.conf" 


describe 'Checking Postgres-databases for risky entries' do
  
  # Req. 15: trusted languages
  describe command("sudo -i psql -d postgres -c \"SELECT count (*) FROM pg_language WHERE lanpltrusted = 'f' AND lanname!='internal' AND lanname!='c';\" | tail -n3 | head -n1 | tr -d ' '") do
    its(:stdout) { should match(/^0/) }
  end
	
  # Req. 5: no empty passwords
  describe command("sudo -i psql -d postgres -c \"SELECT * FROM pg_shadow WHERE passwd IS NULL;\" | tail -n2 | head -n1 | cut -d '(' -f2 | cut -d ' ' -f1") do
    its(:stdout) { should match(/^0/) }
  end

  # Req. 6: MD5-hash
  describe command("sudo -i psql -d postgres -c \"SELECT passwd FROM pg_shadow;\" | tail -n+3 | head -n-2 | grep -v \"md5\" -c") do
    its(:stdout) { should match(/^0/) }
  end                  

end


describe 'Req. 17: Postgres FS-permissions' do
	
  describe command("find #{postgres_home} -user #{user_name} -group #{user_name} -perm /go=rwx | wc -l") do
    its(:stdout) { should match(/^0/) }
  end

end


describe 'Parsing configfiles' do
	
  # Req. 19: ssl = on
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('ssl', 'on') }
  end
  
  # Req. 19: ssl_ciphers = 'ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH'
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('ssl_ciphers', "'ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH'") }
  end  
 
  # Req. 6: password_encryption = on
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('password_encryption', 'on') }
  end 
                  
  # Req. 6: MD5 for ALL connections/users
  describe 'require MD5 for ALL users in pg_hba.conf' do
                  
    describe command("sudo -i cat #{hba_config_file} | grep ' all' | sed 's/  \\+/ /g' | grep 'local all all md5' -c") do
      its(:stdout) { should match(/^1/) }
    end
 
    describe command("sudo -i cat #{hba_config_file} | grep ' all' | sed 's/  \\+/ /g' | grep 'host all all 127.0.0.1/32 md5' -c") do
      its(:stdout) { should match(/^1/) }
    end

    describe command("sudo -i cat #{hba_config_file} | grep ' all' | sed 's/  \\+/ /g' | grep 'host all all ::1/128 md5' -c") do
      its(:stdout) { should match(/^1/) }
    end
  end
                  
  describe file(postgres_config_file) do
    its(:content) { should match_key_value('password_encryption', 'on') }
  end                   
                  
end
