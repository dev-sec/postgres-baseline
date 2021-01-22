# encoding: utf-8

# Copyright 2016, Patrick Muench
# Copyright 2016-2019 DevSec Hardening Framework Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'PostgreSQL Server Configuration'

# inputs
USER = input('user', value: 'postgres')
PASSWORD = input('password', value: 'iloverandompasswordsbutthiswilldo')
POSTGRES_DATA = input('postgres_data', value: postgres.data_dir)
POSTGRES_CONF_DIR = input('postgres_conf_dir', value: postgres.conf_dir)
POSTGRES_CONF_PATH = input('postgres_conf_path', value: postgres.conf_path)
POSTGRES_HBA_CONF_FILE = input('postgres_hba_conf_file', value: File.join(POSTGRES_CONF_DIR.to_s, 'pg_hba.conf'))

only_if do
  command('psql').exist?
end

control 'postgres-01' do
  impact 1.0
  title 'Postgresql should be running'
  desc 'Postgresql should be running.'
  # describe service(postgres.service) do
  #   it { should be_installed }
  #   it { should be_running }
  #   it { should be_enabled }
  # end
  case os[:name]
  when 'ubuntu'
    case os[:release]
    when '12.04'
      describe command('/etc/init.d/postgresql status') do
        its('stdout') { should include 'online' }
      end
    when '14.04'
      describe command('service postgresql status') do
        its('stdout') { should include 'online' }
      end
    when '16.04'
      describe systemd_service(postgres.service) do
        it { should be_installed }
        it { should be_running }
        it { should be_enabled }
      end
    end
  when 'debian'
    case os[:release]
    when /7\./
      describe command('/etc/init.d/postgresql status') do
        its('stdout') { should include 'Running' }
      end
    end
  when 'redhat', 'centos', 'oracle', 'fedora'
      describe command('ps aux | awk /\'bin\/postmaster\'/ | wc -l') do
        its('stdout') { should include '1' }
    end
  end
end

control 'postgres-02' do
  impact 1.0
  title 'Use stable postgresql version'
  desc 'Use only community or commercially supported version of the PostgreSQL software (https://www.postgresql.org/support/versioning/). Do not use RC, DEVEL oder BETA versions in a production environment.'
  describe command('psql -V') do
    its('stdout') { should match(/^psql\s\(PostgreSQL\)\s(9\.[5-6]|10|11|12|13).*/) }
  end
  describe command('psql -V') do
    its('stdout') { should_not match(/RC/) }
    its('stdout') { should_not match(/DEVEL/) }
    its('stdout') { should_not match(/BETA/) }
  end
end

control 'postgres-03' do
  impact 1.0
  title 'Run one postgresql instance per operating system'
  desc 'Only one postgresql database instance must be running on an operating system instance (both physical HW or virtualized).'
  describe command('ps aux | awk /\'bin\/postmaster\'/ | wc -l') do
        its('stdout') { should include '1' }
  end
end

control 'postgres-04' do
  impact 1.0
  title 'Only "c" and "internal" should be used as non-trusted procedural languages'
  desc 'If additional programming languages (e.g. plperl) are installed with non-trust mode, then it is possible to gain OS-level access permissions.'
  describe postgres_session(USER, PASSWORD).query('SELECT count (*) FROM pg_language WHERE lanpltrusted = \'f\' AND lanname!=\'internal\' AND lanname!=\'c\';') do
    its('output') { should eq '0' }
  end
end

control 'postgres-05' do
  impact 1.0
  title 'Set a password for each user'
  desc 'It tests for usernames which does not set a password.'
  describe postgres_session(USER, PASSWORD).query('SELECT count(*) FROM pg_shadow WHERE passwd IS NULL;') do
    its('output') { should eq '0' }
  end
end

control 'postgres-06' do
  impact 1.0
  title 'Use salted hash to store postgresql passwords'
  desc 'Store postgresql passwords in salted hash format (e.g. salted MD5).'
  case postgres.version
  when /^9/
    describe postgres_session(USER, PASSWORD).query('SELECT passwd FROM pg_shadow;') do
      its('output') { should match(/^md5\S*$/i) }
    end
    describe postgres_conf(POSTGRES_CONF_PATH) do
      its('password_encryption') { should eq 'on' }
    end
  else
    describe postgres_session(USER, PASSWORD).query('SELECT passwd FROM pg_shadow;') do
      its('output') { should match(/^scram-sha-256\S*$/i) }
    end
    describe postgres_conf(POSTGRES_CONF_PATH) do
      its('password_encryption') { should eq 'scram-sha-256' }
    end
  end
end

control 'postgres-07' do
  impact 1.0
  title 'Only the postgresql database administrator should have SUPERUSER, CREATEDB or CREATEROLE privileges.'
  desc 'Granting extensive privileges to ordinary users can cause various security problems, such as: intentional/ unintentional access, modification or destroying data'
  describe postgres_session(USER, PASSWORD).query('SELECT count(*) FROM pg_roles WHERE rolsuper IS TRUE OR rolcreaterole IS TRUE or rolcreatedb IS TRUE;') do
    its('output') { should eq '1' }
  end
end

control 'postgres-08' do
  impact 1.0
  title 'Only the DBA should have privileges on pg_catalog.pg_authid table.'
  desc 'In pg_catalog.pg_authid table there are stored credentials such as username and password. If hacker has access to the table, then he can extract these credentials.'
  describe postgres_session(USER, PASSWORD).query("SELECT grantee FROM information_schema.role_table_grants WHERE table_name='pg_authid' group by grantee;") do
    its('output') { should eq 'postgres' }
  end
end

control 'postgres-09' do
  impact 1.0
  title 'The PostgreSQL "data_directory" should be assigned exclusively to the database account (such as "postgres").'
  desc 'If file permissions on data are not property defined, other users may read, modify or delete those files.'
  find_command = 'find ' + POSTGRES_DATA.to_s + ' -user ' + USER + ' -group ' + USER + ' -perm /go=rwx'
  describe command(find_command) do
    its('stdout') { should eq '' }
  end
end

control 'postgres-10' do
  impact 1.0
  title 'The PostgreSQL config directory and file should be assigned exclusively to the database account (such as "postgres").'
  desc 'If file permissions on config files are not property defined, other users may read, modify or delete those files.'
  describe file(POSTGRES_CONF_DIR) do
    it { should be_directory }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
  describe file(POSTGRES_CONF_PATH) do
    it { should be_file }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
  describe file(POSTGRES_HBA_CONF_FILE) do
    it { should be_file }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
end

control 'postgres-11' do
  impact 1.0
  title 'SSL is deactivated just for testing the chef-hardening-cookbook. It is recommended to activate ssl communication.'
  desc 'The hardening-cookbook will delete the links from #var/lib/postgresql/%postgresql-version%/main/server.crt to etc/ssl/certs/ssl-cert-snakeoil.pem and #var/lib/postgresql/%postgresql-version%/main/server.key to etc/ssl/private/ssl-cert-snakeoil.key on Debian systems. This certificates are self-signed (see http://en.wikipedia.org/wiki/Snake_oil_%28cryptography%29) and therefore not trusted. You have to #provide our own trusted certificates for SSL.'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('ssl') { should eq 'off' }
  end
end

control 'postgres-12' do
  impact 1.0
  title 'Use strong chiphers for ssl communication'
  desc 'The following categories of SSL Ciphers must not be used: ADH, LOW, EXP and MD5. A very good description for secure postgres installation / configuration can be found at: https://bettercrypto.org'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('ssl_ciphers') { should eq 'ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH' }
  end
end

control 'postgres-13' do
  impact 1.0
  title 'Require MD5 for ALL users, peers in pg_hba.conf'
  desc 'Require MD5 for ALL users, peers in pg_hba.conf and do not allow untrusted authentication methods.'
  describe file(POSTGRES_HBA_CONF_FILE) do
    its('content') { should match(/local\s.*?all\s.*?all\s.*?md5/) }
    its('content') { should match(%r{host\s.*?all\s.*?all\s.*?127.0.0.1\/32\s.*?md5}) }
    its('content') { should match(%r{host\s.*?all\s.*?all\s.*?::1\/128\s.*?md5}) }
    its('content') { should_not match(/.*password/) }
    its('content') { should_not match(/.*trust/) }
    its('content') { should_not match(/.*crypt/) }
  end
end

control 'postgres-14' do
  impact 1.0
  title 'We accept one peer and one ident for now (chef automation)'
  desc 'We accept one peer and one ident for now (chef automation)'
  describe command('cat ' + POSTGRES_HBA_CONF_FILE.to_s + ' | egrep \'peer|ident\' | wc -l') do
    its('stdout') { should match(/^[2|1]/) }
  end
end

control 'postgres-15' do
  impact 1.0
  title 'Enable logging functions'
  desc 'Logging functions must be turned on and properly configured according / compliant to local law.'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('logging_collector') { should eq 'on' }
    its('log_connections') { should eq 'on' }
    its('log_disconnections') { should eq 'on' }
    its('log_duration') { should eq 'on' }
    its('log_hostname') { should eq 'on' }
    its('log_directory') { should eq 'pg_log' }
    its('log_line_prefix') { should eq '%t %u %d %h' }
  end
end
