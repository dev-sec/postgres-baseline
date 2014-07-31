# Configure Postgresql Server as you normally would:

class { '::postgresql::server':
  postgres_password          => 'iloverandompasswordsbutthiswilldo',
}

class { '::postgres_hardening':
  provider => 'puppetlabs/postgresql'
}
