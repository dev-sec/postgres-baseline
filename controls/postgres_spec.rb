# frozen_string_literal: true

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
USER = input(
  'user',
  description: 'define the postgresql user to access the database',
  value: 'postgres'
)

PASSWORD = input(
  'password',
  description: 'define the postgresql password to access the database',
  value: 'iloverandompasswordsbutthiswilldo'
)

POSTGRES_DATA = input(
  'postgres_data',
  description: 'define the postgresql data directory',
  value: postgres.data_dir
)

POSTGRES_CONF_DIR = input(
  'postgres_conf_dir',
  description: 'define the postgresql configuration directory',
  value: postgres.conf_dir
)

POSTGRES_CONF_PATH = input(
  'postgres_conf_path',
  description: 'define path for the postgresql configuration file',
  value: File.join(POSTGRES_CONF_DIR.to_s, 'postgresql.conf')
)

POSTGRES_HBA_CONF_FILE = input(
  'postgres_hba_conf_file',
  description: 'define path for the postgresql configuration file',
  value: File.join(POSTGRES_CONF_DIR.to_s, 'pg_hba.conf')
)

POSTGRES_LOG_DIR = input(
  'postgres_log_dir',
  description: 'define path for the postgresql log file',
  value: '/var/log/postgresql'
)

only_if do
  command('psql').exist?
end

control 'postgres-01' do
  impact 1.0
  title 'Postgresql should be running'
  desc 'Postgresql should be running.'
  describe service(postgres.service) do
    it { should be_installed }
    it { should be_running }
    it { should be_enabled }
  end
end

control 'postgres-02' do
  impact 1.0
  title 'Use stable postgresql version'
  desc 'Use only community or commercially supported version of the PostgreSQL software (https://www.postgresql.org/support/versioning/). Do not use RC, DEVEL oder BETA versions in a production environment.'
  describe command('psql -V') do
    its('stdout') { should match /^psql\s\(PostgreSQL\)\s(9.6|10|11|12|13).*/ }
  end
  describe command('psql -V') do
    its('stdout') { should_not match /RC/ }
    its('stdout') { should_not match /DEVEL/ }
    its('stdout') { should_not match /BETA/ }
  end
end

control 'postgres-03' do
  impact 1.0
  title 'Run one postgresql instance per operating system'
  desc 'Only one postgresql database instance must be running on an operating system instance (both physical HW or virtualized).'
  case os[:name]
  when 'redhat', 'centos', 'oracle', 'fedora'
    describe processes('bin/postmaster') do
      its('entries.length') { should eq 1 }
    end
  when 'debian', 'ubuntu'
    describe processes('bin/postgres') do
      its('entries.length') { should eq 1 }
    end
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
  title 'Delete not required procedural languages'
  desc 'You should delete programming languages which are not necessary. "internal", "c", "plpgsql" and "sql" are allowed defaults.'
  describe postgres_session(USER, PASSWORD).query("SELECT COUNT(*) FROM pg_language where lanname NOT IN ('internal', 'c', 'sql', 'plpgsql');") do
    its('output') { should eq '0' }
  end
end

control 'postgres-06' do
  impact 1.0
  title 'Set a password for each user'
  desc 'It tests for usernames which does not set a password.'
  describe postgres_session(USER, PASSWORD).query('SELECT count(*) FROM pg_shadow WHERE passwd IS NULL;') do
    its('output') { should eq '0' }
  end
end

control 'postgres-07' do
  impact 1.0
  title 'Use salted hash to store postgresql passwords'
  desc 'Store postgresql passwords in salted hash format (e.g. salted MD5).'
  case postgres.version
  when /^9/
    describe postgres_session(USER, PASSWORD).query('SELECT passwd FROM pg_shadow;') do
      its('output') { should match /^md5\S*$/i }
    end
    describe postgres_session(USER, PASSWORD).query('SHOW password_encryption;') do
      its('output') { should eq 'on' }
    end
  else
    describe postgres_session(USER, PASSWORD).query('SELECT passwd FROM pg_shadow;') do
      its('output') { should match /^scram-sha-256\S*$/i }
    end
    describe postgres_session(USER, PASSWORD).query('SHOW password_encryption;') do
      its('output') { should eq 'scram-sha-256' }
    end
  end
end

control 'postgres-08' do
  impact 1.0
  title 'Only the postgresql database administrator should have SUPERUSER, CREATEDB or CREATEROLE privileges.'
  desc 'Granting extensive privileges to ordinary users can cause various security problems, such as: intentional/ unintentional access, modification or destroying data'
  describe postgres_session(USER, PASSWORD).query('SELECT count(*) FROM pg_roles WHERE rolsuper IS TRUE OR rolcreaterole IS TRUE or rolcreatedb IS TRUE;') do
    its('output') { should eq '1' }
  end
end

control 'postgres-09' do
  impact 1.0
  title 'Only the DBA should have privileges on pg_catalog.pg_authid table.'
  desc 'In pg_catalog.pg_authid table there are stored credentials such as username and password. If hacker has access to the table, then he can extract these credentials.'
  describe postgres_session(USER, PASSWORD).query("SELECT grantee FROM information_schema.role_table_grants WHERE table_name='pg_authid' group by grantee;") do
    its('output') { should eq 'postgres' }
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
    it { should be_readable.by('group') }
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
    it { should be_readable.by('group') }
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
  title 'It is recommended to activate ssl communication.'
  desc 'The hardening-cookbook will delete the links from #var/lib/postgresql/%postgresql-version%/main/server.crt to etc/ssl/certs/ssl-cert-snakeoil.pem and #var/lib/postgresql/%postgresql-version%/main/server.key to etc/ssl/private/ssl-cert-snakeoil.key on Debian systems. This certificates are self-signed (see http://en.wikipedia.org/wiki/Snake_oil_%28cryptography%29) and therefore not trusted. You have to #provide our own trusted certificates for SSL.'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('ssl') { should eq 'on' }
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
  title 'Require peer auth_method for local users'
  desc 'Require peer auth_method for local users.'
  describe postgres_hba_conf(POSTGRES_HBA_CONF_FILE).where { type == 'local' } do
    its('auth_method') { should all eq 'peer' }
  end
end

control 'postgres-14' do
  impact 1.0
  title 'Require only trusted authentication mathods in pg_hba.conf'
  desc 'Require trusted auth method for ALL users, peers in pg_hba.conf and do not allow untrusted authentication methods.'
  case postgres.version
  when /^9/
    describe postgres_hba_conf(POSTGRES_HBA_CONF_FILE).where { type == 'hostssl' } do
      its('auth_method') { should all eq 'md5' }
    end
  else
    describe postgres_hba_conf(POSTGRES_HBA_CONF_FILE).where { type == 'hostssl' } do
      its('auth_method') { should all eq 'scram-sha-256' }
    end
  end
end

control 'postgres-15' do
  impact 1.0
  title 'Require SSL communication between all peers'
  desc 'Do not allow communication without SSL among all peers.'
  describe file(POSTGRES_HBA_CONF_FILE) do
    its('content') { should_not match /^host .*/ }
    its('content') { should_not match /^hostnossl .*/ }
  end
end

control 'postgres-16' do
  impact 1.0
  title 'Enable logging functions'
  desc 'Logging functions must be turned on and properly configured according / compliant to local law.'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('logging_collector') { should eq 'on' }
    its('log_connections') { should eq 'on' }
    its('log_disconnections') { should eq 'on' }
    its('log_duration') { should eq 'on' }
    its('log_hostname') { should eq 'on' }
    its('log_directory') { should_not eq ' ' }
    its('log_line_prefix') { should eq '%t %u %d %h' }
  end
end

control 'postgres-17' do
  impact 1.0
  title 'Grants should not be assigned to public'
  desc 'Grants should not be assigned to public to avoid issues with tenant separations.'
  describe postgres_session(USER, PASSWORD).query("SELECT COUNT(*) FROM information_schema.table_privileges WHERE grantee = 'PUBLIC' AND table_schema NOT LIKE 'pg_catalog' AND table_schema NOT LIKE 'information_schema';") do
    its('output') { should eq '0' }
  end
end

control 'postgres-18' do
  impact 1.0
  title 'Grants should not be assigned with grant option privilege'
  desc 'Grants should not be assigned with grant option exept postgresql admin superuser.'
  describe postgres_session(USER, PASSWORD).query("SELECT COUNT(is_grantable) FROM information_schema.table_privileges WHERE grantee NOT LIKE 'postgres' AND is_grantable = 'YES';") do
    its('output') { should eq '0' }
  end
end

control 'postgres-19' do
  impact 1.0
  title 'Restrictive usage of SQL functions with security definer'
  desc 'Avoid SQL functions with security definer.'
  describe postgres_session(USER, PASSWORD).query("SELECT COUNT(*) FROM pg_proc JOIN pg_namespace ON pg_proc.pronamespace=pg_namespace.oid JOIN pg_user ON pg_proc.proowner=pg_user.usesysid WHERE prosecdef='t';") do
    its('output') { should eq '0' }
  end
end

control 'postgres-20' do
  impact 1.0
  title 'The PostgreSQL data and log directory should be assigned exclusively to the database account (such as "postgres").'
  desc 'The PostgreSQL data and log directory should be assigned exclusively to the database account (such as "postgres").'
  describe file(POSTGRES_DATA) do
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
  describe file(POSTGRES_LOG_DIR) do
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
end
